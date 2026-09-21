import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated } from "@/lib/site-settings";
import { Field, PasswordField, SectionTitle, SelectField, Toggle, useUnsavedGuard } from "@/components/admin/settings-ui";
import {
  RiLoader4Line, RiRefreshLine, RiSaveLine, RiSendPlane2Line,
  RiCheckLine, RiAlertLine, RiInformationLine, RiMailLine,
} from "@remixicon/react";

type EmailConfigStatus = {
  status: "ok" | "partial" | "unconfigured";
  provider: string;
  hint: string;
  smtpEnabled: boolean;
  smtpHost: string;
  smtpUser: string;
  smtpPass: boolean;
  resendApiKey: boolean;
};

type TestEmailResult = { key: string; subject: string; ok: boolean; error?: string };

export default function AdminEmailSettingsPage() {
  const [s, setS] = React.useState<SiteSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [dirty, setDirty] = React.useState(false);
  useUnsavedGuard(dirty);

  const [configStatus, setConfigStatus] = React.useState<EmailConfigStatus | null>(null);
  const [checking, setChecking] = React.useState(false);
  const [testTo, setTestTo] = React.useState("");
  const [testing, setTesting] = React.useState(false);
  const [testResults, setTestResults] = React.useState<TestEmailResult[] | null>(null);

  React.useEffect(() => {
    setLoading(true);
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(d => {
        if (d.settings) setS({ ...DEFAULT_SETTINGS, ...d.settings });
      })
      .catch(() => toast.error("加载设置失败"))
      .finally(() => setLoading(false));
  }, []);

  const checkConfig = React.useCallback(async () => {
    setChecking(true);
    try {
      const res = await fetch("/api/admin/test-email");
      if (res.ok) {
        const data = await res.json();
        setConfigStatus(data);
      } else {
        toast.error("检查邮件配置失败");
      }
    } catch {
      toast.error("网络错误，请重试");
    } finally {
      setChecking(false);
    }
  }, []);

  React.useEffect(() => { checkConfig(); }, [checkConfig]);

  function set(key: keyof SiteSettings, value: string) {
    setS(prev => ({ ...prev, [key]: value }));
    setDirty(true);
  }

  async function save() {
    setSaving(true);
    try {
      const res = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(s),
      });
      if (!res.ok) {
        const data = await res.json();
        toast.error(data.error || "保存失败");
        return;
      }
      toast.success("设置已保存");
      setDirty(false);
      notifySettingsUpdated();
    } catch {
      toast.error("保存失败，请重试");
    } finally {
      setSaving(false);
    }
  }

  async function reload() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/settings");
      const data = await res.json();
      if (data.settings) {
        setS({ ...DEFAULT_SETTINGS, ...data.settings });
        setDirty(false);
        toast.success("已重新加载");
      }
    } catch {
      toast.error("加载失败");
    } finally {
      setLoading(false);
    }
  }

  const sendTestEmail = async () => {
    if (!testTo.trim()) { toast.error("请输入收件人邮箱"); return; }
    setTesting(true);
    setTestResults(null);
    try {
      const res = await fetch("/api/admin/test-email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to: testTo.trim(), template: "welcome" }),
      });
      const data = await res.json();
      if (data.ok) {
        toast.success(`测试邮件已发送至 ${testTo.trim()}`);
      } else {
        toast.error("发送失败：" + (data.results?.[0]?.error || data.error || "未知错误"));
      }
      if (data.results) setTestResults(data.results);
    } catch {
      toast.error("网络错误，请重试");
    } finally {
      setTesting(false);
    }
  };

  const statusColor = configStatus?.status === "ok"
    ? "text-green-600 bg-green-50 border-green-200 dark:bg-green-950/30 dark:border-green-800/40"
    : configStatus?.status === "partial"
      ? "text-amber-600 bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:border-amber-800/40"
      : "text-red-600 bg-red-50 border-red-200 dark:bg-red-950/30 dark:border-red-800/40";

  const StatusIcon = configStatus?.status === "ok" ? RiCheckLine
    : configStatus?.status === "partial" ? RiInformationLine
    : RiAlertLine;

  return (
    <AdminLayout title="邮件配置">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-lg font-bold">邮件配置</h1>
          <p className="text-xs text-muted-foreground mt-0.5">SMTP 与 Resend 发信配置，用于注册验证、密码重置等系统邮件</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={reload} disabled={loading} className="gap-1.5 text-xs">
            <RiRefreshLine className="w-3.5 h-3.5" />
            刷新
          </Button>
          <Button size="sm" onClick={save} disabled={saving || loading} className="gap-1.5 text-xs">
            {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
            {dirty ? "保存更改" : "已保存"}
          </Button>
        </div>
      </div>

      {dirty && (
        <div className="mb-4 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400">
          <span className="text-xs font-medium">有未保存的更改，请记得点击「保存更改」</span>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <SectionTitle icon={RiMailLine} title="邮件发送状态" desc="当前邮件服务配置诊断" effect="邮件通知" />
              <Button size="sm" variant="outline" onClick={checkConfig} disabled={checking} className="shrink-0 text-xs h-7 px-2.5">
                {checking ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiRefreshLine className="w-3.5 h-3.5" />}
                <span className="ml-1">{checking ? "检查中…" : "刷新"}</span>
              </Button>
            </div>
            {configStatus ? (
              <div className={cn("flex items-start gap-3 p-3 rounded-xl border text-xs", statusColor)}>
                <StatusIcon className="w-4 h-4 mt-0.5 shrink-0" />
                <div>
                  <p className="font-semibold">{configStatus.provider}</p>
                  <p className="mt-0.5 opacity-80">{configStatus.hint}</p>
                </div>
              </div>
            ) : checking ? (
              <div className="flex items-center gap-2 text-xs text-muted-foreground p-3">
                <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> 检查中…
              </div>
            ) : null}

            <div className="space-y-2 pt-2 border-t border-border">
              <p className="text-xs font-semibold">发送测试邮件</p>
              <div className="flex gap-2">
                <Input
                  type="email"
                  value={testTo}
                  onChange={e => setTestTo(e.target.value)}
                  placeholder="收件邮箱（默认发送 Welcome 模板）"
                  className="text-xs flex-1"
                  onKeyDown={e => { if (e.key === "Enter") sendTestEmail(); }}
                />
                <Button size="sm" onClick={sendTestEmail} disabled={testing || !testTo.trim()} className="shrink-0 text-xs">
                  {testing ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiSendPlane2Line className="w-3.5 h-3.5 mr-1" />}
                  {testing ? "发送中…" : "发送"}
                </Button>
              </div>
              {testResults && (
                <div className="space-y-1">
                  {testResults.map(r => (
                    <div key={r.key} className={cn("flex items-start gap-2 text-[11px] p-2 rounded-lg border", r.ok ? "border-green-200 bg-green-50 text-green-700 dark:bg-green-950/30 dark:border-green-800/40 dark:text-green-400" : "border-red-200 bg-red-50 text-red-700 dark:bg-red-950/30 dark:border-red-800/40 dark:text-red-400")}>
                      {r.ok ? <RiCheckLine className="w-3.5 h-3.5 mt-0.5 shrink-0" /> : <RiAlertLine className="w-3.5 h-3.5 mt-0.5 shrink-0" />}
                      <span>{r.ok ? `已发送：${r.subject}` : `失败：${r.error}`}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiMailLine} title="SMTP 邮件配置" desc="用于发送注册验证、密码重置等系统邮件" effect="邮件通知" />
            <Toggle
              label="启用 SMTP"
              checked={s.smtp_enabled === "1"}
              onChange={v => set("smtp_enabled", v ? "1" : "")}
            />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="SMTP 主机">
                <Input value={s.smtp_host} onChange={e => set("smtp_host", e.target.value)} placeholder="smtp.example.com" className="text-xs" />
              </Field>
              <Field label="SMTP 端口">
                <Input value={s.smtp_port} onChange={e => set("smtp_port", e.target.value)} placeholder="465" type="number" className="text-xs" />
              </Field>
              <Field label="SMTP 用户名">
                <Input value={s.smtp_user} onChange={e => set("smtp_user", e.target.value)} placeholder="noreply@example.com" className="text-xs" />
              </Field>
              <PasswordField label="SMTP 密码" value={s.smtp_pass} onChange={v => set("smtp_pass", v)} />
              <Field label="发件人地址">
                <Input value={s.smtp_from} onChange={e => set("smtp_from", e.target.value)} placeholder="域见你 <noreply@example.com>" className="text-xs" />
              </Field>
              <SelectField
                label="加密方式"
                value={s.smtp_secure}
                onChange={v => set("smtp_secure", v)}
                options={[
                  { value: "ssl",      label: "SSL/TLS（端口 465）" },
                  { value: "starttls", label: "STARTTLS（端口 587）" },
                  { value: "none",     label: "不加密（不推荐）" },
                ]}
              />
            </div>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiMailLine} title="Resend 邮件配置" desc="使用 Resend 服务发送邮件（与 SMTP 二选一）" effect="邮件通知" />
            <PasswordField label="Resend API Key" desc="从 resend.com 后台获取" value={s.resend_api_key} onChange={v => set("resend_api_key", v)} placeholder="re_..." />
            <Field label="发件人地址">
              <Input value={s.resend_from_email} onChange={e => set("resend_from_email", e.target.value)} placeholder="域见你 <noreply@example.com>" className="text-xs" />
            </Field>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}