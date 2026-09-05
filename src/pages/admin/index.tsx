import React from "react";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { getPageCache, setPageCache } from "@/lib/page-cache";
import { cn } from "@/lib/utils";
import {
  RiUserLine, RiShieldCheckLine, RiBellLine, RiSearchLine,
  RiSettings4Line, RiLoader4Line, RiArrowRightLine,
  RiFeedbackLine, RiTimeLine, RiGhostLine, RiVipCrownLine,
  RiAddLine, RiBankCardLine,
  RiRefreshLine, RiPlugLine,
  RiShieldUserLine, RiFireLine, RiServerLine,
  RiCodeBoxLine, RiMoneyDollarCircleLine,
  RiPaletteLine, RiGithubLine,
  RiLinksLine, RiImageLine, RiHeart3Line, RiHistoryLine,
  RiGlobalLine, RiMailSendLine, RiDownloadLine,
  RiBillLine, RiAlertLine, RiBarChartLine,
  RiNotification3Line, RiNetworkLine, RiWifiLine,
} from "@remixicon/react";

type Stats = {
  users: number;
  disabledUsers: number;
  stamps: number;
  verifiedStamps: number;
  activeReminders: number;
  searches: number;
  feedback: number;
  anonSearches: number;
  loggedSearches: number;
  todaySearches: number;
  todayAnonSearches: number;
  todayLoggedSearches: number;
  todayUsers: number;
  subscribedUsers: number;
  totalOrders: number;
  paidOrders: number;
  paidRevenue: number;
  tldFailures: number;
  weeklySearches: number;
  failedDomainSearches: number;
  todayFailedSearches: number;
  failureRate: number;
  queryTypeBreakdown: { domain: number; ip: number; asn: number; cidr: number };
  regStatusBreakdown: { available: number; registered: number; highValue: number };
  topFailingTlds: { tld: string; fail_count: number; fail_reason: string | null; has_custom_server: boolean }[];
  dailyTrend: { day: string; count: number }[];
  dailySignups: { day: string; count: number }[];
  dailyRevenue: { day: string; revenue: number }[];
  recentUsers: { id: string; email: string; name: string | null; created_at: string; disabled: boolean }[];
  recentSearches: { id: string; query: string; query_type: string; created_at: string; user_id: string | null; reg_status: string | null }[];
};

function Sparkline({ data, color = "#3b82f6", h = 28, w = 72 }: { data: number[]; color?: string; h?: number; w?: number }) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x},${y}`;
  }).join(" ");
  const fill = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * h;
    return `${x},${y}`;
  });
  const area = `M0,${h} L${fill.join(" L")} L${w},${h} Z`;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} fill="none" className="shrink-0">
      <path d={area} fill={color} fillOpacity={0.12} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={fill[fill.length - 1].split(",")[0]} cy={fill[fill.length - 1].split(",")[1]} r={2} fill={color} />
    </svg>
  );
}

function StatCard({ icon: Icon, label, value, sub, subValue, href, color, badge, sparkline, sparklineColor }: {
  icon: React.ElementType;
  label: string;
  value: number | string | undefined;
  sub?: string;
  subValue?: number | string;
  href: string;
  color: string;
  badge?: { label: string; value: number; color: string };
  sparkline?: number[];
  sparklineColor?: string;
}) {
  const router = useRouter();
  return (
    <button
      type="button"
      onClick={() => router.push(href, undefined, { locale: false })}
      className="glass-panel border border-border rounded-2xl p-3 sm:p-4 flex items-start gap-3 hover:border-primary/30 hover:bg-primary/5 transition-all group text-left w-full min-w-0 active:scale-[0.98]"
    >
      <div className={`w-8 h-8 sm:w-9 sm:h-9 rounded-xl flex items-center justify-center shrink-0 ${color}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-muted-foreground font-medium truncate">{label}</p>
        <p className="text-xl sm:text-2xl font-bold tabular-nums mt-0.5 truncate">
          {value === undefined ? <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground" /> : (typeof value === "number" ? value.toLocaleString() : value)}
        </p>
        {sub && subValue !== undefined && (
          <p className="text-[10px] text-muted-foreground/70 mt-0.5">{sub}: {typeof subValue === "number" ? subValue.toLocaleString() : subValue}</p>
        )}
        {badge && badge.value > 0 && (
          <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-semibold mt-1 inline-block ${badge.color}`}>
            {badge.label} {badge.value}
          </span>
        )}
      </div>
      <div className="flex flex-col items-end gap-1 shrink-0">
        <RiArrowRightLine className="w-3.5 h-3.5 text-muted-foreground group-hover:text-primary transition-colors" />
        {sparkline && sparkline.length >= 2 && (
          <Sparkline data={sparkline} color={sparklineColor ?? "#3b82f6"} h={24} w={60} />
        )}
      </div>
    </button>
  );
}

function fmt(d: string) {
  const date = new Date(d);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return "刚刚";
  if (mins < 60) return `${mins} 分钟前`;
  if (hours < 24) return `${hours} 小时前`;
  if (days < 7) return `${days} 天前`;
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

type ActionItem = { href: string; label: string; desc: string; icon: React.ElementType; color: string };
type ActionGroup = { label: string; accentColor: string; items: ActionItem[] };

function QuickActionGroup({ group }: { group: ActionGroup }) {
  const router = useRouter();
  return (
    <div className="space-y-2">
      <p className={`text-[10px] font-bold uppercase tracking-widest ${group.accentColor} flex items-center gap-1.5`}>
        {group.label}
      </p>
      <div className="grid grid-cols-1 min-[420px]:grid-cols-2 sm:grid-cols-4 gap-1.5">
        {group.items.map(({ href, label, desc, icon: Icon, color }) => (
          <button
            key={href}
            type="button"
            onClick={() => router.push(href, undefined, { locale: false })}
            className="glass-panel border border-border/60 rounded-xl p-2.5 hover:border-primary/30 hover:bg-primary/5 transition-all group text-left active:scale-[0.98]"
          >
            <Icon className={`w-3.5 h-3.5 shrink-0 ${color} mb-1.5`} />
            <p className="text-[11px] font-semibold group-hover:text-primary transition-colors leading-tight">{label}</p>
            <p className="text-[10px] text-muted-foreground leading-snug mt-0.5 hidden sm:block">{desc}</p>
          </button>
        ))}
      </div>
    </div>
  );
}

const ACTION_GROUPS: ActionGroup[] = [
  {
    label: "用户与支付",
    accentColor: "text-violet-500",
    items: [
      { href: "/admin/users",            label: "用户管理",    desc: "账号、停用、手动订阅",       icon: RiUserLine,       color: "text-violet-500" },
      { href: "/admin/payment/plans",    label: "订阅套餐",    desc: "定价策略与功能权益配置",     icon: RiVipCrownLine,   color: "text-indigo-500" },
      { href: "/admin/payment/orders",   label: "支付订单",    desc: "流水明细与对账管理",         icon: RiBillLine,       color: "text-green-500" },
      { href: "/admin/access-control",   label: "访问控制",    desc: "API 密钥·邀请码·激活码",     icon: RiShieldUserLine, color: "text-slate-500" },
    ],
  },
  {
    label: "通知与服务",
    accentColor: "text-cyan-500",
    items: [
      { href: "/admin/reminders",        label: "到期提醒",    desc: "域名监控与续费订阅管理",     icon: RiBellLine,           color: "text-cyan-500" },
      { href: "/admin/notify",           label: "邮件推送",    desc: "向用户发送群发通知邮件",     icon: RiMailSendLine,       color: "text-blue-400" },
      { href: "/admin/notify-service",   label: "通知渠道",    desc: "Bark·Telegram·钉钉·飞书·Webhook", icon: RiNotification3Line, color: "text-indigo-500" },
      { href: "/admin/expired-domains",  label: "过期域名挖掘", desc: "抓取短域名·高价值·AI前缀域名", icon: RiGlobalLine,    color: "text-emerald-600" },
      { href: "/admin/feedback",         label: "用户反馈",    desc: "处理与回应用户反馈",         icon: RiFeedbackLine,   color: "text-rose-500" },
      { href: "/admin/search-records",   label: "查询记录",    desc: "浏览、统计、清理历史记录",   icon: RiSearchLine,     color: "text-emerald-500" },
    ],
  },
  {
    label: "域名与接入",
    accentColor: "text-blue-500",
    items: [
      { href: "/admin/domain-access",           label: "域名接入",     desc: "接入监控总览与 TLD 分布",    icon: RiNetworkLine,    color: "text-blue-500" },
      { href: "/admin/tld-rules",               label: "TLD 规则",     desc: "AI爬取·WHOIS/RDAP 规则定制", icon: RiCodeBoxLine,    color: "text-teal-500" },
      { href: "/admin/tld-rules?inner=failures",label: "查询失败记录", desc: "后缀失败分析·一键添加服务器", icon: RiAlertLine,      color: "text-amber-500" },
      { href: "/admin/tld-failures",            label: "失败详细统计", desc: "完整失败统计·repair·第三方API",icon: RiBarChartLine,   color: "text-orange-500" },
      { href: "/admin/tld-rules?inner=lifecycle",label: "生命周期设置", desc: "宽限期·赎回期·用户纠错审核",  icon: RiTimeLine,       color: "text-blue-600" },
      { href: "/admin/query-logs",              label: "查询日志",     desc: "实时请求日志与错误率监控",   icon: RiHistoryLine,    color: "text-sky-500" },
      { href: "/admin/api",                     label: "API 集成",     desc: "AI Key · 第三方数据源配置",  icon: RiPlugLine,       color: "text-orange-500" },
      { href: "/admin/hot-prefixes",            label: "热门搜索词",   desc: "首页推荐查询词条管理",       icon: RiFireLine,       color: "text-red-500" },
    ],
  },
  {
    label: "品牌与内容",
    accentColor: "text-fuchsia-500",
    items: [
      { href: "/admin/stamps",           label: "品牌认领审核", desc: "审核用户提交的认领申请",    icon: RiShieldCheckLine,color: "text-amber-500" },
      { href: "/admin/stamp-styles",     label: "印章样式",     desc: "品牌卡片主题风格配置",      icon: RiPaletteLine,    color: "text-fuchsia-500" },
      { href: "/admin/og-styles",        label: "OG 分享图",    desc: "链接预览图布局与配色",      icon: RiImageLine,      color: "text-indigo-400" },
      { href: "/admin/links",            label: "友情链接",     desc: "外部推荐链接管理",          icon: RiLinksLine,      color: "text-blue-400" },
      { href: "/admin/sponsors",         label: "赞助商",       desc: "合作伙伴与赞助商展示",      icon: RiHeart3Line,     color: "text-rose-500" },
      { href: "/admin/changelog",        label: "更新日志",     desc: "版本记录与公告发布",        icon: RiHistoryLine,    color: "text-emerald-500" },
    ],
  },
  {
    label: "系统与设置",
    accentColor: "text-gray-500",
    items: [
      { href: "/admin/settings",    label: "网站设置",  desc: "标题、公告、功能开关",       icon: RiSettings4Line, color: "text-blue-500" },
      { href: "/admin/system",      label: "系统监控",  desc: "数据库连接与运行状态",       icon: RiServerLine,    color: "text-gray-500" },
      { href: "/admin/tld-speed",   label: "服务器测速", desc: "WHOIS 服务器延迟与可达性",  icon: RiWifiLine,      color: "text-cyan-500" },
      { href: "/admin/server-test", label: "服务器测试", desc: "手动测试 WHOIS/RDAP 接入",  icon: RiPlugLine,      color: "text-violet-500" },
      { href: "/admin/db-export",   label: "数据导出",  desc: "导出数据库记录与备份",       icon: RiDownloadLine,  color: "text-green-600" },
    ],
  },
];

export default function AdminIndexPage() {
  const router = useRouter();
  const [stats, setStats] = React.useState<Stats | null>(() => getPageCache<Stats>("admin_stats"));
  const [error, setError] = React.useState<string | null>(null);
  const [refreshing, setRefreshing] = React.useState(false);

  function loadStats(force = false) {
    setRefreshing(true);
    setError(null);
    const url = force ? "/api/admin/stats?refresh=1" : "/api/admin/stats";
    fetch(url)
      .then(r => r.json())
      .then(data => {
        if (data.error) setError(data.error);
        else {
          setStats(data);
          setPageCache("admin_stats", data, 3 * 60_000);
        }
      })
      .catch(() => setError("加载失败"))
      .finally(() => setRefreshing(false));
  }

  React.useEffect(() => {
    // Skip fetch if we already have fresh cached data
    if (stats) return;
    loadStats();
  }, []);

  return (
    <AdminLayout title="概览">
      <div className="space-y-5">

        {/* Header */}
        <div className="flex items-center justify-between gap-3 min-w-0">
          <div className="min-w-0">
            <h2 className="text-lg font-bold">后台概览</h2>
            <p className="text-xs text-muted-foreground mt-0.5">数据实时汇总 · 快捷导航</p>
          </div>
          <button
            onClick={() => loadStats(true)}
            disabled={refreshing}
            className="p-2 rounded-xl hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
            title="刷新统计"
          >
            <RiRefreshLine className={cn("w-4 h-4", refreshing && "animate-spin")} />
          </button>
        </div>

        {error && (
          <div className="glass-panel border border-red-200/50 bg-red-50/30 dark:bg-red-950/20 rounded-xl p-4">
            <p className="text-sm text-red-500">{error}</p>
          </div>
        )}

        {/* Today quick bar */}
        {stats && (stats.todayUsers > 0 || stats.todaySearches > 0) && (
          <div className="glass-panel border border-primary/20 bg-primary/5 rounded-xl px-4 py-2.5 flex items-center gap-4 flex-wrap">
            <span className="text-[11px] font-bold text-primary">今日动态</span>
            {stats.todayUsers > 0 && (
              <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                <RiAddLine className="w-3 h-3 text-emerald-500" />
                <span className="font-semibold text-foreground">{stats.todayUsers}</span> 新用户
              </span>
            )}
            {stats.todaySearches > 0 && (
              <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                <RiSearchLine className="w-3 h-3 text-blue-500" />
                <span className="font-semibold text-foreground">{stats.todaySearches}</span> 次查询
                {stats.todayLoggedSearches > 0 && (
                  <span className="text-primary/70">（登录 {stats.todayLoggedSearches}</span>
                )}
                {stats.todayAnonSearches > 0 && (
                  <span className="text-muted-foreground/70">匿名 {stats.todayAnonSearches}）</span>
                )}
              </span>
            )}
            {(stats.todayFailedSearches ?? 0) > 0 && (
              <button
                onClick={() => router.push("/admin/tld-failures", undefined, { locale: false })}
                className="text-[11px] text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1 hover:underline"
              >
                <RiAlertLine className="w-3 h-3" />
                今日失败 {stats.todayFailedSearches}
                {stats.failureRate > 0 && <span className="text-muted-foreground font-normal">（{stats.failureRate}%）</span>}
              </button>
            )}
            {(stats.feedback ?? 0) > 0 && (
              <button
                onClick={() => router.push("/admin/feedback", undefined, { locale: false })}
                className="text-[11px] text-rose-500 font-semibold flex items-center gap-1 hover:underline"
              >
                <RiFeedbackLine className="w-3 h-3" />
                {stats.feedback} 条待处理反馈
              </button>
            )}
          </div>
        )}

        {/* Core stats grid */}
        <div className="grid grid-cols-1 min-[420px]:grid-cols-2 sm:grid-cols-3 gap-2.5">
          <StatCard
            icon={RiUserLine} label="注册用户" value={stats?.users}
            sub="已停用" subValue={stats?.disabledUsers}
            href="/admin/users"
            color="bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400"
            badge={stats?.subscribedUsers ? { label: "订阅", value: stats.subscribedUsers, color: "bg-amber-100 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400" } : undefined}
            sparkline={stats?.dailySignups?.map(d => d.count)}
            sparklineColor="#6366f1"
          />
          <StatCard
            icon={RiShieldCheckLine} label="品牌认领" value={stats?.stamps}
            sub="已认证" subValue={stats?.verifiedStamps}
            href="/admin/stamps"
            color="bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400"
          />
          <StatCard
            icon={RiSearchLine} label="查询总量" value={stats?.searches}
            sub="今日新增" subValue={stats?.todaySearches}
            href="/admin/search-records"
            color="bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400"
            sparkline={stats?.dailyTrend?.map(d => d.count)}
            sparklineColor="#f97316"
          />
          <StatCard
            icon={RiBellLine} label="到期监控" value={stats?.activeReminders}
            sub="活跃提醒" subValue={undefined}
            href="/admin/reminders"
            color="bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400"
          />
          <StatCard
            icon={RiFeedbackLine} label="用户反馈" value={stats?.feedback}
            href="/admin/feedback"
            color="bg-pink-100 dark:bg-pink-950/40 text-pink-600 dark:text-pink-400"
          />
          {(stats?.paidRevenue ?? 0) > 0 ? (
            <StatCard
              icon={RiMoneyDollarCircleLine} label="已收营收"
              value={stats ? `¥${stats.paidRevenue.toFixed(2)}` : undefined}
              sub="已付款" subValue={stats?.paidOrders}
              href="/admin/payment/orders"
              color="bg-lime-100 dark:bg-lime-950/40 text-lime-600 dark:text-lime-400"
              sparkline={stats?.dailyRevenue?.map(d => d.revenue)}
              sparklineColor="#84cc16"
            />
          ) : (
            <StatCard
              icon={RiVipCrownLine} label="订阅用户" value={stats?.subscribedUsers}
              sub="总用户" subValue={stats?.users}
              href="/admin/users"
              color="bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400"
            />
          )}
          {(stats?.totalOrders ?? 0) > 0 && (
            <StatCard
              icon={RiBankCardLine} label="支付订单" value={stats?.totalOrders}
              sub="已付款" subValue={stats?.paidOrders}
              href="/admin/payment/orders"
              color="bg-teal-100 dark:bg-teal-950/40 text-teal-600 dark:text-teal-400"
            />
          )}
          <StatCard
            icon={RiAlertLine} label="查询失败域名" value={stats?.failedDomainSearches}
            sub="今日失败" subValue={stats ? `${stats.todayFailedSearches}（${stats.failureRate}%）` : undefined}
            href="/admin/tld-failures"
            color="bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400"
            badge={stats?.tldFailures ? { label: "后缀异常", value: stats.tldFailures, color: "bg-orange-100 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400" } : undefined}
          />
        </div>

        {/* Recent users + searches side by side */}
        {(stats?.recentUsers?.length ?? 0) > 0 || (stats?.recentSearches?.length ?? 0) > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {stats?.recentUsers && stats.recentUsers.length > 0 && (
              <div className="glass-panel border border-border rounded-2xl p-4 space-y-2.5">
                <div className="flex items-center gap-2 justify-between">
                  <h3 className="text-xs font-bold flex items-center gap-1.5">
                    <RiTimeLine className="w-3.5 h-3.5 text-primary" />最近注册
                  </h3>
                  <button onClick={() => router.push("/admin/users", undefined, { locale: false })} className="text-[11px] text-primary hover:underline">全部</button>
                </div>
                <div className="space-y-1.5">
                  {stats.recentUsers.map(u => (
                    <div key={u.id} className="flex items-center gap-2.5">
                      <div className="w-6 h-6 rounded-full bg-gradient-to-br from-primary/20 to-violet-500/20 flex items-center justify-center shrink-0">
                        <RiUserLine className="w-3 h-3 text-primary" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] font-semibold truncate">{u.name || u.email}</p>
                        {u.name && <p className="text-[10px] text-muted-foreground truncate">{u.email}</p>}
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {u.disabled && (
                          <span className="text-[9px] px-1 py-0.5 rounded bg-red-100 dark:bg-red-950/30 text-red-600 dark:text-red-400 font-semibold">停用</span>
                        )}
                        <span className="text-[10px] text-muted-foreground">{fmt(u.created_at)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {stats?.recentSearches && stats.recentSearches.length > 0 && (
              <div className="glass-panel border border-border rounded-2xl p-4 space-y-2.5">
                <div className="flex items-center gap-2 justify-between">
                  <h3 className="text-xs font-bold flex items-center gap-1.5">
                    <RiSearchLine className="w-3.5 h-3.5 text-primary" />最近查询
                  </h3>
                  <button onClick={() => router.push("/admin/search-records", undefined, { locale: false })} className="text-[11px] text-primary hover:underline">全部</button>
                </div>
                <div className="space-y-1">
                  {stats.recentSearches.map(s => (
                    <div key={s.id} className="flex items-center gap-1.5 rounded-lg px-0 py-0.5">
                      {!s.user_id && <RiGhostLine className="w-2.5 h-2.5 text-muted-foreground/40 shrink-0" />}
                      <span className="text-[9px] text-muted-foreground uppercase font-mono shrink-0 w-9">{s.query_type}</span>
                      <span className="text-[11px] font-mono font-semibold truncate flex-1">{s.query}</span>
                      {s.reg_status && (
                        <span className={cn(
                          "text-[9px] px-1 py-0.5 rounded font-semibold shrink-0",
                          s.reg_status === "registered" ? "bg-emerald-100 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400" :
                          s.reg_status === "unregistered" ? "bg-blue-100 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400" :
                          "bg-muted text-muted-foreground"
                        )}>
                          {s.reg_status === "registered" ? "已注册" : s.reg_status === "unregistered" ? "可注册" : s.reg_status}
                        </span>
                      )}
                      {!s.reg_status && s.query_type === "domain" && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-amber-100 dark:bg-amber-950/30 text-amber-600 dark:text-amber-400 font-semibold shrink-0">失败</span>
                      )}
                      <span className="text-[10px] text-muted-foreground shrink-0">{fmt(s.created_at)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* Query type breakdown + top failing TLDs */}
        {stats && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {/* Query type breakdown */}
            <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
              <div className="flex items-center gap-2 justify-between">
                <h3 className="text-xs font-bold flex items-center gap-1.5">
                  <RiBarChartLine className="w-3.5 h-3.5 text-primary" />查询类型分布
                </h3>
                <button onClick={() => router.push("/admin/search-records", undefined, { locale: false })} className="text-[11px] text-primary hover:underline">详情</button>
              </div>
              {(() => {
                const b = stats.queryTypeBreakdown;
                const total = (b.domain + b.ip + b.asn + b.cidr) || 1;
                const items = [
                  { label: "域名", value: b.domain, color: "bg-blue-500" },
                  { label: "IP",   value: b.ip,     color: "bg-violet-500" },
                  { label: "ASN",  value: b.asn,    color: "bg-amber-500" },
                  { label: "CIDR", value: b.cidr,   color: "bg-rose-500" },
                ];
                return (
                  <div className="space-y-2">
                    <div className="flex h-2 rounded-full overflow-hidden gap-0.5">
                      {items.map(it => it.value > 0 && (
                        <div key={it.label} className={cn("rounded-full", it.color)} style={{ width: `${Math.max((it.value / total) * 100, 1)}%` }} />
                      ))}
                    </div>
                    <div className="grid grid-cols-2 gap-x-3 gap-y-1">
                      {items.map(it => (
                        <div key={it.label} className="flex items-center gap-1.5">
                          <div className={cn("w-2 h-2 rounded-full shrink-0", it.color)} />
                          <span className="text-[10px] text-muted-foreground">{it.label}</span>
                          <span className="text-[10px] font-semibold ml-auto">{it.value.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                    <div className="pt-1 border-t border-border/40 grid grid-cols-2 gap-x-3 gap-y-1">
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                        <span className="text-[10px] text-muted-foreground">可注册</span>
                        <span className="text-[10px] font-semibold ml-auto">{stats.regStatusBreakdown.available.toLocaleString()}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full bg-orange-500 shrink-0" />
                        <span className="text-[10px] text-muted-foreground">高价值</span>
                        <span className="text-[10px] font-semibold ml-auto">{stats.regStatusBreakdown.highValue.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Top failing TLDs */}
            {stats.topFailingTlds.length > 0 && (
              <div className="glass-panel border border-amber-200/50 dark:border-amber-800/30 rounded-2xl p-4 space-y-2.5">
                <div className="flex items-center gap-2 justify-between">
                  <h3 className="text-xs font-bold flex items-center gap-1.5">
                    <RiAlertLine className="w-3.5 h-3.5 text-amber-500" />查询失败后缀 Top 8
                  </h3>
                  <button onClick={() => router.push("/admin/tld-failures", undefined, { locale: false })} className="text-[11px] text-primary hover:underline">全部</button>
                </div>
                <div className="space-y-1">
                  {stats.topFailingTlds.map(t => {
                    const reasons: Record<string, string> = {
                      iana_fallback: "无服务器", no_server: "无可达", timeout: "超时",
                      parse_error: "解析错误", rate_limited: "速率限制",
                    };
                    return (
                      <div key={t.tld} className="flex items-center gap-2">
                        <code className="text-[10px] font-mono font-semibold shrink-0 w-20 truncate">.{t.tld}</code>
                        <span className="text-[9px] text-muted-foreground shrink-0">{reasons[t.fail_reason ?? ""] ?? t.fail_reason ?? "—"}</span>
                        {t.has_custom_server && <span className="text-[9px] text-emerald-500 shrink-0">✓</span>}
                        <div className="flex-1" />
                        <span className="text-[10px] font-bold text-red-500 shrink-0">{t.fail_count.toLocaleString()}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Quick actions — grouped */}
        <div className="glass-panel border border-border rounded-2xl p-4 space-y-4">
          <h3 className="text-sm font-bold flex items-center gap-2">
            <RiSettings4Line className="w-4 h-4 text-primary" />功能导航
          </h3>
          <div className="space-y-4 divide-y divide-border/40">
            {ACTION_GROUPS.map((group, i) => (
              <div key={group.label} className={i > 0 ? "pt-4" : ""}>
                <QuickActionGroup group={group} />
              </div>
            ))}
          </div>
        </div>

      </div>
    </AdminLayout>
  );
}
