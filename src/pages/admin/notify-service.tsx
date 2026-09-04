import React from "react";
import { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  RiLoader4Line,
  RiSaveLine,
  RiCheckLine,
  RiCloseLine,
  RiFlashlightLine,
  RiEyeLine,
  RiEyeOffLine,
  RiBellLine,
  RiMailLine,
  RiSmartphoneLine,
  RiGlobalLine,
  RiWechatLine,
  RiLinksLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import type { SiteSettings } from "@/lib/site-settings";
import { DEFAULT_SETTINGS } from "@/lib/site-settings";

type NotifySettings = Pick<
  SiteSettings,
  | "smtp_enabled"
  | "smtp_host"
  | "smtp_from"
  | "notify_bark_url"
  | "notify_telegram_token"
  | "notify_telegram_chat_id"
  | "notify_dingding_webhook"
  | "notify_feishu_webhook"
  | "notify_wecom_webhook"
  | "notify_generic_webhook"
  | "notify_generic_webhook_method"
>;

const NOTIFY_KEYS: (keyof NotifySettings)[] = [
  "smtp_enabled", "smtp_host", "smtp_from",
  "notify_bark_url",
  "notify_telegram_token", "notify_telegram_chat_id",
  "notify_dingding_webhook",
  "notify_feishu_webhook",
  "notify_wecom_webhook",
  "notify_generic_webhook", "notify_generic_webhook_method",
];

function ChannelCard({
  icon: Icon,
  title,
  desc,
  badge,
  badgeColor,
  children,
}: {
  icon: React.ElementType;
  title: string;
  desc: string;
  badge?: string;
  badgeColor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-xl bg-muted/60 flex items-center justify-center shrink-0">
          <Icon className="w-5 h-5 text-muted-foreground" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-sm font-semibold">{title}</h3>
            {badge && (
              <span className={cn("text-[10px] font-semibold px-2 py-0.5 rounded-full", badgeColor || "bg-muted text-muted-foreground")}>
                {badge}
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function SecretInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const [show, setShow] = React.useState(false);
  return (
    <div className="relative">
      <Input
        type={show ? "text" : "password"}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="text-xs pr-9 font-mono"
        autoComplete="off"
      />
      <button
        type="button"
        onClick={() => setShow(s => !s)}
        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
      >
        {show ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}

function TestButton({
  channel,
  label,
  onTest,
  testing,
  result,
}: {
  channel: string;
  label?: string;
  onTest: (channel: string) => Promise<void>;
  testing: string | null;
  result: { ok: boolean; message: string } | null;
}) {
  const busy = testing === channel;
  return (
    <div className="flex items-center gap-2 flex-wrap pt-1">
      <Button
        size="sm"
        variant="outline"
        onClick={() => onTest(channel)}
        disabled={!!testing}
        className="text-xs h-7"
      >
        {busy ? <RiLoader4Line className="w-3 h-3 mr-1 animate-spin" /> : <RiFlashlightLine className="w-3 h-3 mr-1" />}
        {label || "发送测试"}
      </Button>
      {result && (
        <span className={cn("text-xs flex items-center gap-1", result.ok ? "text-green-600" : "text-red-500")}>
          {result.ok ? <RiCheckLine className="w-3.5 h-3.5" /> : <RiCloseLine className="w-3.5 h-3.5" />}
          {result.message}
        </span>
      )}
    </div>
  );
}

export default function AdminNotifyServicePage() {
  const [s, setS] = React.useState<NotifySettings>(() => {
    const d: Partial<NotifySettings> = {};
    NOTIFY_KEYS.forEach(k => (d[k] = DEFAULT_SETTINGS[k] as any));
    return d as NotifySettings;
  });
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState<string | null>(null);
  const [testResults, setTestResults] = React.useState<Record<string, { ok: boolean; message: string }>>({});

  React.useEffect(() => {
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(d => {
        if (d.settings) {
          const next: Partial<NotifySettings> = {};
          NOTIFY_KEYS.forEach(k => {
            next[k] = (d.settings[k] ?? DEFAULT_SETTINGS[k]) as any;
          });
          setS(next as NotifySettings);
        }
      })
      .catch(() => toast.error("加载设置失败"))
      .finally(() => setLoading(false));
  }, []);

  function set<K extends keyof NotifySettings>(k: K, v: NotifySettings[K]) {
    setS(prev => ({ ...prev, [k]: v }));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const res = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(s),
      });
      const d = await res.json().catch(() => ({}));
      if (res.ok && d.ok !== false) toast.success("通知服务配置已保存");
      else toast.error(d.error || "保存失败");
    } catch {
      toast.error("保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(channel: string) {
    setTesting(channel);
    setTestResults(prev => ({ ...prev, [channel]: { ok: false, message: "测试中..." } }));
    try {
      const res = await fetch("/api/admin/notify-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel }),
      });
      const d = await res.json();
      setTestResults(prev => ({ ...prev, [channel]: { ok: d.ok, message: d.message } }));
      if (d.ok) toast.success(d.message);
      else toast.error(d.message);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "测试失败";
      setTestResults(prev => ({ ...prev, [channel]: { ok: false, message: msg } }));
      toast.error(msg);
    } finally {
      setTesting(null);
    }
  }

  if (loading) {
    return (
      <AdminLayout title="通知服务">
        <div className="flex items-center justify-center min-h-[200px]">
          <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      </AdminLayout>
    );
  }

  const emailConfigured = !!(s.smtp_enabled && s.smtp_host);

  return (
    <AdminLayout title="通知服务">
      <div className="max-w-2xl space-y-6 pb-10">

        {/* Header */}
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiBellLine className="w-5 h-5 text-primary" />
              通知服务
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              配置到期提醒、系统通知的推送渠道。支持邮件、Bark、Telegram、钉钉、飞书、企业微信及通用 Webhook。
            </p>
          </div>
          <Button onClick={handleSave} disabled={saving} size="sm" className="shrink-0">
            {saving ? <RiLoader4Line className="w-4 h-4 mr-1.5 animate-spin" /> : <RiSaveLine className="w-4 h-4 mr-1.5" />}
            保存配置
          </Button>
        </div>

        {/* Email Channel (readonly status, config in Settings) */}
        <ChannelCard
          icon={RiMailLine}
          title="邮件通知"
          desc="通过 SMTP 发送到期提醒和系统通知邮件"
          badge={emailConfigured ? "已配置" : "未配置"}
          badgeColor={emailConfigured ? "bg-green-100 dark:bg-green-950/40 text-green-700 dark:text-green-400" : "bg-muted text-muted-foreground"}
        >
          <div className="text-xs text-muted-foreground bg-muted/40 rounded-xl px-4 py-3 space-y-1">
            <p>邮件渠道配置请前往 <span className="font-semibold text-foreground">网站设置 → 邮件配置</span> 进行管理。</p>
            {emailConfigured && (
              <p className="text-green-600 dark:text-green-400 font-medium">✓ SMTP 已配置 · 发件服务器: {s.smtp_host}</p>
            )}
            {!emailConfigured && (
              <p className="text-amber-600 dark:text-amber-400 font-medium">⚠ 未配置 SMTP，到期提醒邮件将无法发送</p>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            className="text-xs h-7"
            onClick={() => window.open("/admin/settings?tab=email", "_self")}
          >
            前往邮件配置
          </Button>
        </ChannelCard>

        {/* Bark */}
        <ChannelCard
          icon={RiSmartphoneLine}
          title="Bark 推送"
          desc="通过 Bark App 向 iOS 设备推送通知（需安装 Bark App）"
          badge="iOS"
          badgeColor="bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400"
        >
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground font-medium">Bark Server URL</label>
            <SecretInput
              value={s.notify_bark_url}
              onChange={v => set("notify_bark_url", v)}
              placeholder="https://api.day.app/xxxxxxxxxx"
            />
            <p className="text-[11px] text-muted-foreground">
              在 Bark App 中复制 Server URL，格式为 https://api.day.app/&lt;KEY&gt;
            </p>
          </div>
          <TestButton
            channel="bark"
            onTest={handleTest}
            testing={testing}
            result={testResults["bark"] || null}
          />
        </ChannelCard>

        {/* Telegram */}
        <ChannelCard
          icon={RiGlobalLine}
          title="Telegram Bot"
          desc="通过 Telegram 机器人发送通知消息"
          badge="Bot"
          badgeColor="bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400"
        >
          <div className="space-y-3">
            <div className="space-y-2">
              <label className="text-xs text-muted-foreground font-medium">Bot Token</label>
              <SecretInput
                value={s.notify_telegram_token}
                onChange={v => set("notify_telegram_token", v)}
                placeholder="1234567890:ABCDEFGxxxxxxxxxxxxxxxxxxxxxxx"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs text-muted-foreground font-medium">Chat ID</label>
              <Input
                value={s.notify_telegram_chat_id}
                onChange={e => set("notify_telegram_chat_id", e.target.value)}
                placeholder="-100xxxxxxxxxxxxxxx 或 @channelname"
                className="text-xs font-mono"
              />
              <p className="text-[11px] text-muted-foreground">
                通过 @userinfobot 获取 Chat ID；频道/群组需要以 -100 开头
              </p>
            </div>
          </div>
          <TestButton
            channel="telegram"
            onTest={handleTest}
            testing={testing}
            result={testResults["telegram"] || null}
          />
        </ChannelCard>

        {/* DingTalk */}
        <ChannelCard
          icon={RiBellLine}
          title="钉钉 Webhook"
          desc="通过钉钉群机器人推送消息"
          badge="钉钉"
          badgeColor="bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400"
        >
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground font-medium">Webhook URL</label>
            <SecretInput
              value={s.notify_dingding_webhook}
              onChange={v => set("notify_dingding_webhook", v)}
              placeholder="https://oapi.dingtalk.com/robot/send?access_token=xxx"
            />
            <p className="text-[11px] text-muted-foreground">
              在钉钉群聊 → 群设置 → 智能群助手 → 添加机器人 → 自定义机器人中获取 Webhook 地址
            </p>
          </div>
          <TestButton
            channel="dingding"
            onTest={handleTest}
            testing={testing}
            result={testResults["dingding"] || null}
          />
        </ChannelCard>

        {/* Feishu */}
        <ChannelCard
          icon={RiLinksLine}
          title="飞书 Webhook"
          desc="通过飞书群机器人推送消息"
          badge="飞书"
          badgeColor="bg-cyan-100 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-400"
        >
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground font-medium">Webhook URL</label>
            <SecretInput
              value={s.notify_feishu_webhook}
              onChange={v => set("notify_feishu_webhook", v)}
              placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
            />
            <p className="text-[11px] text-muted-foreground">
              在飞书群聊设置中添加机器人，选择"自定义机器人"获取 Webhook 地址
            </p>
          </div>
          <TestButton
            channel="feishu"
            onTest={handleTest}
            testing={testing}
            result={testResults["feishu"] || null}
          />
        </ChannelCard>

        {/* WeCom */}
        <ChannelCard
          icon={RiWechatLine}
          title="企业微信 Webhook"
          desc="通过企业微信群机器人推送消息"
          badge="企业微信"
          badgeColor="bg-green-100 dark:bg-green-950/40 text-green-700 dark:text-green-400"
        >
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground font-medium">Webhook URL</label>
            <SecretInput
              value={s.notify_wecom_webhook}
              onChange={v => set("notify_wecom_webhook", v)}
              placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
            />
            <p className="text-[11px] text-muted-foreground">
              在企业微信群聊中添加机器人，右键复制 Webhook 地址
            </p>
          </div>
          <TestButton
            channel="wecom"
            onTest={handleTest}
            testing={testing}
            result={testResults["wecom"] || null}
          />
        </ChannelCard>

        {/* Generic Webhook */}
        <ChannelCard
          icon={RiLinksLine}
          title="通用 Webhook"
          desc="向自定义 URL 发送 JSON 格式的通知请求"
          badge="自定义"
          badgeColor="bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400"
        >
          <div className="space-y-3">
            <div className="space-y-2">
              <label className="text-xs text-muted-foreground font-medium">Webhook URL</label>
              <Input
                value={s.notify_generic_webhook}
                onChange={e => set("notify_generic_webhook", e.target.value)}
                placeholder="https://your-service.com/webhook"
                className="text-xs font-mono"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs text-muted-foreground font-medium">请求方法</label>
              <div className="flex gap-2">
                {(["POST", "GET", "PUT"] as const).map(m => (
                  <button
                    key={m}
                    onClick={() => set("notify_generic_webhook_method", m)}
                    className={cn(
                      "text-xs px-3 py-1.5 rounded-lg border font-mono font-semibold transition-colors",
                      s.notify_generic_webhook_method === m
                        ? "bg-primary text-primary-foreground border-primary"
                        : "border-border text-muted-foreground hover:border-primary/50"
                    )}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </div>
            <div className="bg-muted/40 rounded-xl px-4 py-3 text-[11px] text-muted-foreground space-y-1">
              <p className="font-medium text-foreground">发送格式（JSON Body）:</p>
              <pre className="font-mono text-[10px]">{`{ "title": "...", "body": "...", "timestamp": 0, "source": "your-site.com" }`}</pre>
            </div>
          </div>
          <TestButton
            channel="generic"
            onTest={handleTest}
            testing={testing}
            result={testResults["generic"] || null}
          />
        </ChannelCard>

        <div className="flex justify-end pt-2">
          <Button onClick={handleSave} disabled={saving}>
            {saving ? <RiLoader4Line className="w-4 h-4 mr-1.5 animate-spin" /> : <RiSaveLine className="w-4 h-4 mr-1.5" />}
            保存所有配置
          </Button>
        </div>
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
