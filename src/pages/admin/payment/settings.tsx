import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { PaymentTabs } from "@/components/admin/payment-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated } from "@/lib/site-settings";
import { Field, PasswordField, SectionTitle, SelectField, TextareaField, Toggle, useUnsavedGuard } from "@/components/admin/settings-ui";
import { RiLoader4Line, RiRefreshLine, RiSaveLine, RiMoneyDollarCircleLine, RiBankCardLine } from "@remixicon/react";

export default function AdminPaymentSettingsPage() {
  const [s, setS] = React.useState<SiteSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [dirty, setDirty] = React.useState(false);
  useUnsavedGuard(dirty);

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

  return (
    <AdminLayout title="支付配置">
      <PaymentTabs />

      {/* Header */}
      <div className="flex items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-lg font-bold">支付配置</h1>
          <p className="text-xs text-muted-foreground mt-0.5">平台收款渠道（Stripe、PayPal、虎皮椒、支付宝、微信）与货币设置。所有密钥字段均加密存储</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={reload} disabled={loading} className="gap-1.5 text-xs">
            <RiRefreshLine className={saving ? "w-3.5 h-3.5 animate-spin" : "w-3.5 h-3.5"} />
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
            <SectionTitle icon={RiMoneyDollarCircleLine} title="通用支付设置" effect="后台" />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <SelectField
                label="支付货币"
                value={s.payment_currency}
                onChange={v => set("payment_currency", v)}
                options={[
                  { value: "CNY", label: "CNY — 人民币" },
                  { value: "USD", label: "USD — 美元" },
                  { value: "EUR", label: "EUR — 欧元" },
                  { value: "HKD", label: "HKD — 港币" },
                ]}
              />
              <Field label="支付成功跳转 URL">
                <Input value={s.payment_success_url} onChange={e => set("payment_success_url", e.target.value)} placeholder="https://yourdomain.com/dashboard" className="text-xs" />
              </Field>
            </div>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiBankCardLine} title="Stripe" effect="后台" />
            <Toggle label="启用 Stripe 支付" checked={s.payment_stripe_enabled === "1"} onChange={v => set("payment_stripe_enabled", v ? "1" : "")} />
            <Field label="Publishable Key (pk_)">
              <Input value={s.payment_stripe_pk} onChange={e => set("payment_stripe_pk", e.target.value)} placeholder="pk_live_..." className="text-xs" />
            </Field>
            <PasswordField label="Secret Key (sk_)" value={s.payment_stripe_sk} onChange={v => set("payment_stripe_sk", v)} placeholder="sk_live_..." />
            <PasswordField label="Webhook Secret" value={s.payment_stripe_webhook_secret} onChange={v => set("payment_stripe_webhook_secret", v)} placeholder="whsec_..." />
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiBankCardLine} title="PayPal" effect="后台" />
            <Toggle label="启用 PayPal 支付" checked={s.payment_paypal_enabled === "1"} onChange={v => set("payment_paypal_enabled", v ? "1" : "")} />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="Client ID">
                <Input value={s.payment_paypal_client_id} onChange={e => set("payment_paypal_client_id", e.target.value)} placeholder="AXxx..." className="text-xs" />
              </Field>
              <PasswordField label="Client Secret" value={s.payment_paypal_client_secret} onChange={v => set("payment_paypal_client_secret", v)} />
              <Field label="Webhook ID">
                <Input value={s.payment_paypal_webhook_id} onChange={e => set("payment_paypal_webhook_id", e.target.value)} placeholder="Webhook ID" className="text-xs" />
              </Field>
              <SelectField
                label="环境"
                value={s.payment_paypal_env}
                onChange={v => set("payment_paypal_env", v)}
                options={[
                  { value: "live",    label: "live — 生产环境" },
                  { value: "sandbox", label: "sandbox — 沙盒测试" },
                ]}
              />
            </div>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiBankCardLine} title="虎皮椒 (XunhuPay · 支付宝渠道)" effect="后台" />
            <Toggle label="启用虎皮椒支付宝" checked={s.payment_xunhupay_enabled === "1"} onChange={v => set("payment_xunhupay_enabled", v ? "1" : "")} />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="AppID">
                <Input value={s.payment_xunhupay_appid} onChange={e => set("payment_xunhupay_appid", e.target.value)} placeholder="AppID" className="text-xs" />
              </Field>
              <PasswordField label="AppSecret" value={s.payment_xunhupay_secret} onChange={v => set("payment_xunhupay_secret", v)} />
            </div>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiBankCardLine} title="微信支付 (WeChat Pay · 虎皮椒网关)" effect="后台" />
            <Toggle label="启用微信支付" checked={s.payment_wechat_enabled === "1"} onChange={v => set("payment_wechat_enabled", v ? "1" : "")} />
            <p className="text-xs text-muted-foreground">微信支付通过虎皮椒网关处理，复用上方配置的虎皮椒 AppID 和 AppSecret，无需重复填写。启用前请确保虎皮椒账户已开通微信支付渠道。</p>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <SectionTitle icon={RiBankCardLine} title="支付宝 (Alipay)" effect="后台" />
            <Toggle label="启用支付宝支付" checked={s.payment_alipay_enabled === "1"} onChange={v => set("payment_alipay_enabled", v ? "1" : "")} />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="AppID">
                <Input value={s.payment_alipay_appid} onChange={e => set("payment_alipay_appid", e.target.value)} placeholder="2021000000..." className="text-xs" />
              </Field>
              <Field label="异步通知 URL">
                <Input value={s.payment_alipay_notify_url} onChange={e => set("payment_alipay_notify_url", e.target.value)} placeholder="https://yourdomain.com/api/payment/alipay/notify" className="text-xs" />
              </Field>
              <div className="sm:col-span-2">
                <TextareaField label="支付宝公钥" value={s.payment_alipay_public_key} onChange={v => set("payment_alipay_public_key", v)} placeholder="-----BEGIN PUBLIC KEY-----..." rows={3} />
              </div>
              <div className="sm:col-span-2">
                <PasswordField label="应用私钥" value={s.payment_alipay_private_key} onChange={v => set("payment_alipay_private_key", v)} placeholder="-----BEGIN PRIVATE KEY-----..." />
              </div>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}