import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiAddLine, RiDeleteBinLine, RiEditLine,
  RiHeart3Fill, RiUserLine, RiCalendarLine, RiCopperCoinLine,
  RiSaveLine, RiCloseLine, RiEyeLine, RiEyeOffLine,
  RiAlipayLine, RiWechatLine, RiGithubLine, RiImageLine,
  RiMessage2Line, RiExternalLinkLine, RiPaypalLine, RiBitCoinLine,
  RiUploadLine, RiCheckLine,
} from "@remixicon/react";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated } from "@/lib/site-settings";

function ImageUploadField({
  value,
  onChange,
  label,
  hint,
  accept = "image/*",
}: {
  value: string;
  onChange: (url: string) => void;
  label: string;
  hint?: string;
  accept?: string;
}) {
  const [uploading, setUploading] = React.useState(false);
  const [preview, setPreview] = React.useState<string | null>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = async (e) => {
      const dataUrl = e.target?.result as string;
      setPreview(dataUrl);
      setUploading(true);
      try {
        const res = await fetch("/api/admin/upload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ dataUrl, hint }),
        });
        const data = await res.json();
        if (data.url) { onChange(data.url); toast.success("上传成功"); }
        else toast.error(data.error || "上传失败");
      } catch { toast.error("上传失败"); }
      finally { setUploading(false); }
    };
    reader.onerror = () => {
      setUploading(false);
      toast.error("读取文件失败，请重试");
    };
    reader.readAsDataURL(file);
  }

  const isDataUrl = value.startsWith("data:image/");
  const imgSrc = preview || (isDataUrl ? value : value.startsWith("http") || value.startsWith("/") ? value : null);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <div className="flex-1">
          <Input
            value={isDataUrl ? "" : value}
            onChange={e => { onChange(e.target.value); setPreview(null); }}
            placeholder={isDataUrl ? "📎 已上传图片（直接上传新图片可替换）" : "https://... 或点击上传"}
            className="h-8 text-xs font-mono"
            readOnly={isDataUrl}
          />
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={uploading}
          onClick={() => fileRef.current?.click()}
          className="h-8 px-2 text-xs gap-1 shrink-0"
        >
          {uploading ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiUploadLine className="w-3 h-3" />}
          {uploading ? "上传中…" : "上传图片"}
        </Button>
        <input
          ref={fileRef}
          type="file"
          accept={accept}
          className="hidden"
          onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); e.target.value = ""; }}
        />
      </div>
      {imgSrc && (
        <div className="relative group w-32 h-32 rounded-xl border border-border overflow-hidden bg-muted/30 flex items-center justify-center">
          <img src={imgSrc} alt={label} className="w-full h-full object-contain" />
          {isDataUrl && (
            <button
              type="button"
              onClick={() => { onChange(""); setPreview(null); }}
              className="absolute top-1 right-1 w-5 h-5 rounded-full bg-destructive text-white flex items-center justify-center opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
              title="清除图片"
            >
              <span className="text-[10px] font-bold">×</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}

type Sponsor = {
  id: string;
  name: string;
  avatar_url: string | null;
  amount: string | null;
  currency: string;
  message: string | null;
  sponsor_date: string | null;
  is_anonymous: boolean;
  is_visible: boolean;
  platform: string | null;
  created_at: string;
};

const CURRENCY_SYMBOL: Record<string, string> = { CNY: "¥", USD: "$", EUR: "€", JPY: "¥", GBP: "£" };

const EMPTY_FORM = {
  name: "", avatar_url: "", amount: "", currency: "CNY", message: "",
  sponsor_date: "", is_anonymous: false, is_visible: true, platform: "",
};

function SponsorForm({
  initial,
  onSave,
  onCancel,
}: {
  initial: typeof EMPTY_FORM & { id?: string };
  onSave: (data: typeof EMPTY_FORM & { id?: string }) => Promise<void>;
  onCancel: () => void;
}) {
  const [form, setForm] = React.useState(initial);
  const [saving, setSaving] = React.useState(false);

  function set(k: string, v: string | boolean) { setForm(f => ({ ...f, [k]: v })); }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name.trim()) { toast.error("赞助者名称不能为空"); return; }
    setSaving(true);
    try { await onSave(form); } finally { setSaving(false); }
  }

  return (
    <form onSubmit={submit} className="space-y-4 p-4 bg-muted/30 rounded-xl border border-border">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <Label className="text-xs mb-1 block">赞助者名称 *</Label>
          <Input value={form.name} onChange={e => set("name", e.target.value)} placeholder="姓名 / 昵称" className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1 block">平台来源</Label>
          <Input value={form.platform} onChange={e => set("platform", e.target.value)} placeholder="支付宝 / 微信 / GitHub" className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1 block">金额</Label>
          <Input type="number" step="0.01" min="0" value={form.amount} onChange={e => set("amount", e.target.value)} placeholder="0.00" className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1 block">货币</Label>
          <select value={form.currency} onChange={e => set("currency", e.target.value)} className="h-8 w-full text-sm rounded-md border border-input bg-background px-2">
            <option value="CNY">CNY ¥</option>
            <option value="USD">USD $</option>
            <option value="EUR">EUR €</option>
            <option value="JPY">JPY ¥</option>
            <option value="GBP">GBP £</option>
          </select>
        </div>
        <div>
          <Label className="text-xs mb-1 block">赞助日期</Label>
          <Input type="date" value={form.sponsor_date} onChange={e => set("sponsor_date", e.target.value)} className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1 block">头像 URL</Label>
          <Input value={form.avatar_url} onChange={e => set("avatar_url", e.target.value)} placeholder="https://..." className="h-8 text-sm" />
        </div>
      </div>
      <div>
        <Label className="text-xs mb-1 block">留言</Label>
        <textarea
          value={form.message}
          onChange={e => set("message", e.target.value)}
          placeholder="赞助者留言（可选）"
          rows={2}
          className="w-full text-sm rounded-md border border-input bg-background px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>
      <div className="flex items-center gap-4">
        <label className="flex items-center gap-2 cursor-pointer text-sm">
          <input type="checkbox" checked={form.is_anonymous} onChange={e => set("is_anonymous", e.target.checked)} className="rounded" />
          匿名显示
        </label>
        <label className="flex items-center gap-2 cursor-pointer text-sm">
          <input type="checkbox" checked={form.is_visible} onChange={e => set("is_visible", e.target.checked)} className="rounded" />
          公开展示
        </label>
      </div>
      <div className="flex gap-2 pt-1">
        <Button type="submit" size="sm" disabled={saving} className="gap-1.5 text-xs">
          {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
          {initial.id ? "更新" : "添加"}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel} className="text-xs">取消</Button>
      </div>
    </form>
  );
}

function SponsorSettingsPanel() {
  const [settings, setSettings] = React.useState<Partial<SiteSettings>>({});
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(d => { if (d.settings) setSettings(d.settings); })
      .catch(() => {});
  }, []);

  function set(k: string, v: string) { setSettings(s => ({ ...s, [k]: v })); }

  async function save() {
    setSaving(true);
    try {
      const r = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enable_sponsor:      settings.enable_sponsor,
          sponsor_page_title:  settings.sponsor_page_title,
          sponsor_page_desc:   settings.sponsor_page_desc,
          sponsor_alipay_qr:   settings.sponsor_alipay_qr,
          sponsor_wechat_qr:   settings.sponsor_wechat_qr,
          sponsor_github_url:  settings.sponsor_github_url,
          sponsor_paypal_url:  settings.sponsor_paypal_url,
          sponsor_crypto_btc:          settings.sponsor_crypto_btc,
          sponsor_crypto_eth:          settings.sponsor_crypto_eth,
          sponsor_crypto_usdt:         settings.sponsor_crypto_usdt,
          sponsor_crypto_usdt_network: settings.sponsor_crypto_usdt_network,
          sponsor_crypto_okx:          settings.sponsor_crypto_okx,
          sponsor_extra_links: settings.sponsor_extra_links,
        }),
      });
      const d = await r.json();
      if (d.ok) { toast.success("赞助设置已保存"); notifySettingsUpdated(); }
      else toast.error(d.error || "保存失败");
    } catch { toast.error("保存失败"); }
    finally { setSaving(false); }
  }

  return (
    <div className="space-y-5 p-5 rounded-xl border border-border bg-card">
      <h3 className="text-sm font-semibold flex items-center gap-2">
        <RiHeart3Fill className="w-4 h-4 text-rose-500" /> 赞助页面配置
      </h3>

      <label className="flex items-center gap-2 cursor-pointer text-sm font-medium">
        <input type="checkbox" checked={!!settings.enable_sponsor} onChange={e => set("enable_sponsor", e.target.checked ? "1" : "")} className="rounded" />
        启用赞助页面（显示在导航）
      </label>

      {/* Page text */}
      <div className="grid grid-cols-1 gap-3">
        <div>
          <Label className="text-xs mb-1.5 flex items-center gap-1"><RiMessage2Line className="w-3.5 h-3.5" /> 页面标题</Label>
          <Input value={settings.sponsor_page_title || ""} onChange={e => set("sponsor_page_title", e.target.value)} placeholder="赞助支持" className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1.5 block">页面描述</Label>
          <textarea
            value={settings.sponsor_page_desc || ""}
            onChange={e => set("sponsor_page_desc", e.target.value)}
            rows={2}
            placeholder="感谢您对本项目的支持！"
            className="w-full text-sm rounded-md border border-input bg-background px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
      </div>

      {/* QR codes */}
      <div className="space-y-3 pt-2 border-t border-border/50">
        <p className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
          <RiImageLine className="w-3.5 h-3.5" />扫码支付（支付宝 / 微信）
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <Label className="text-xs mb-1.5 flex items-center gap-1 text-blue-600 dark:text-blue-400">
              <RiAlipayLine className="w-3.5 h-3.5" /> 支付宝收款码
            </Label>
            <ImageUploadField
              label="支付宝收款码"
              value={settings.sponsor_alipay_qr || ""}
              onChange={v => set("sponsor_alipay_qr", v)}
              hint="alipay_qr"
            />
          </div>
          <div>
            <Label className="text-xs mb-1.5 flex items-center gap-1 text-green-600 dark:text-green-400">
              <RiWechatLine className="w-3.5 h-3.5" /> 微信收款码
            </Label>
            <ImageUploadField
              label="微信收款码"
              value={settings.sponsor_wechat_qr || ""}
              onChange={v => set("sponsor_wechat_qr", v)}
              hint="wechat_qr"
            />
          </div>
        </div>
      </div>

      {/* Link payments */}
      <div className="space-y-3 pt-2 border-t border-border/50">
        <p className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
          <RiPaypalLine className="w-3.5 h-3.5" />链接支付（GitHub / PayPal）
        </p>
        <div className="grid grid-cols-1 gap-3">
          <div>
            <Label className="text-xs mb-1.5 flex items-center gap-1">
              <RiGithubLine className="w-3.5 h-3.5" /> GitHub Sponsors URL
            </Label>
            <Input value={settings.sponsor_github_url || ""} onChange={e => set("sponsor_github_url", e.target.value)} placeholder="https://github.com/sponsors/yourname" className="h-8 text-sm" />
          </div>
          <div>
            <Label className="text-xs mb-1.5 flex items-center gap-1 text-[#003087] dark:text-blue-400">
              <RiPaypalLine className="w-3.5 h-3.5" /> PayPal 收款链接
            </Label>
            <Input value={settings.sponsor_paypal_url || ""} onChange={e => set("sponsor_paypal_url", e.target.value)} placeholder="https://paypal.me/yourname" className="h-8 text-sm" />
          </div>
        </div>
      </div>

      {/* Crypto */}
      <div className="space-y-3 pt-2 border-t border-border/50">
        <p className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
          <RiBitCoinLine className="w-3.5 h-3.5" />加密货币收款地址（留空则隐藏）
        </p>
        <div className="grid grid-cols-1 gap-3">
          {([
            { key: "sponsor_crypto_btc",  label: "BTC (Bitcoin)", placeholder: "bc1q...", color: "text-amber-600 dark:text-amber-400" },
            { key: "sponsor_crypto_eth",  label: "ETH (Ethereum)", placeholder: "0x...", color: "text-indigo-600 dark:text-indigo-400" },
            { key: "sponsor_crypto_usdt", label: "USDT 钱包地址", placeholder: "T... 或 0x...", color: "text-teal-600 dark:text-teal-400" },
            { key: "sponsor_crypto_usdt_network", label: "USDT 转账网络（如 TRC20 (Tron)）", placeholder: "TRC20 (Tron)", color: "text-teal-600 dark:text-teal-400" },
            { key: "sponsor_crypto_okx",  label: "OKX / Web3 钱包", placeholder: "0x...", color: "text-slate-600 dark:text-slate-400" },
          ] as const).map(({ key, label, placeholder, color }) => (
            <div key={key}>
              <Label className={cn("text-xs mb-1.5 flex items-center gap-1", color)}>
                <RiBitCoinLine className="w-3 h-3" />{label}
              </Label>
              <Input
                value={(settings as any)[key] || ""}
                onChange={e => set(key, e.target.value)}
                placeholder={placeholder}
                className="h-8 text-xs font-mono"
              />
            </div>
          ))}
        </div>
      </div>

      <Button size="sm" onClick={save} disabled={saving} className="gap-1.5 text-xs">
        {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
        保存赞助配置
      </Button>
    </div>
  );
}

export default function AdminSponsorsPage() {
  const [sponsors, setSponsors] = React.useState<Sponsor[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [showForm, setShowForm] = React.useState(false);
  const [editing, setEditing] = React.useState<Sponsor | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  function load() {
    setLoading(true);
    fetch("/api/admin/sponsors")
      .then(r => r.json())
      .then(d => { if (d.sponsors) setSponsors(d.sponsors); })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load(); }, []);

  async function handleAdd(data: typeof EMPTY_FORM) {
    try {
      const r = await fetch("/api/admin/sponsors", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const d = await r.json();
      if (d.ok) { toast.success("赞助记录已添加"); setShowForm(false); load(); }
      else toast.error(d.error || "添加失败");
    } catch {
      toast.error("添加失败：网络错误");
    }
  }

  async function handleEdit(data: typeof EMPTY_FORM & { id?: string }) {
    try {
      const r = await fetch("/api/admin/sponsors", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: editing?.id, ...data }),
      });
      const d = await r.json();
      if (d.ok) { toast.success("已更新"); setEditing(null); load(); }
      else toast.error(d.error || "更新失败");
    } catch {
      toast.error("更新失败：网络错误");
    }
  }

  async function handleDelete(id: string, name: string) {
    if (!confirm(`确定要删除「${name}」的赞助记录吗？`)) return;
    setDeleting(id);
    try {
      const r = await fetch("/api/admin/sponsors", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const d = await r.json();
      if (d.ok) { toast.success("已删除"); load(); }
      else toast.error(d.error || "删除失败");
    } catch {
      toast.error("删除失败：网络错误");
    } finally { setDeleting(null); }
  }

  async function toggleVisible(s: Sponsor) {
    try {
      const r = await fetch("/api/admin/sponsors", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...s, is_visible: !s.is_visible }),
      });
      const d = await r.json();
      if (d.ok) { toast.success(s.is_visible ? "已隐藏" : "已显示"); load(); }
      else toast.error(d.error || "操作失败");
    } catch {
      toast.error("操作失败：网络错误");
    }
  }

  const totalAmount = sponsors.reduce((s, sp) => s + (sp.amount ? parseFloat(sp.amount) : 0), 0);

  return (
    <AdminLayout title="赞助管理">
      <div className="space-y-6">

        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "赞助者总数", value: sponsors.length, icon: <RiUserLine className="w-4 h-4" />, color: "text-rose-500" },
            { label: "累计金额（¥）", value: `¥${totalAmount.toFixed(0)}`, icon: <RiCopperCoinLine className="w-4 h-4" />, color: "text-amber-500" },
            { label: "公开展示", value: sponsors.filter(s => s.is_visible).length, icon: <RiEyeLine className="w-4 h-4" />, color: "text-emerald-500" },
          ].map(stat => (
            <div key={stat.label} className="p-4 rounded-xl border border-border bg-card flex items-center gap-3">
              <span className={stat.color}>{stat.icon}</span>
              <div>
                <div className="text-lg font-bold">{stat.value}</div>
                <div className="text-[11px] text-muted-foreground">{stat.label}</div>
              </div>
            </div>
          ))}
        </div>

        <SponsorSettingsPanel />

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <RiHeart3Fill className="w-4 h-4 text-rose-500" /> 赞助记录
              <span className="text-muted-foreground font-normal">({sponsors.length})</span>
            </h3>
            <Button size="sm" onClick={() => { setShowForm(true); setEditing(null); }} className="gap-1.5 text-xs">
              <RiAddLine className="w-3.5 h-3.5" /> 添加记录
            </Button>
          </div>

          {showForm && !editing && (
            <SponsorForm
              initial={{ ...EMPTY_FORM }}
              onSave={handleAdd}
              onCancel={() => setShowForm(false)}
            />
          )}

          {loading ? (
            <div className="flex justify-center py-10">
              <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : sponsors.length === 0 ? (
            <div className="text-center py-10 text-muted-foreground text-sm border border-dashed border-border rounded-xl">
              <RiHeart3Fill className="w-8 h-8 mx-auto mb-2 opacity-20" />
              <p>暂无赞助记录，点击「添加记录」开始</p>
            </div>
          ) : (
            <div className="space-y-2">
              {sponsors.map(s => (
                <div key={s.id}>
                  {editing?.id === s.id ? (
                    <SponsorForm
                      initial={{
                        name: s.name, avatar_url: s.avatar_url || "", amount: s.amount || "",
                        currency: s.currency, message: s.message || "", sponsor_date: s.sponsor_date?.slice(0, 10) || "",
                        is_anonymous: s.is_anonymous, is_visible: s.is_visible, platform: s.platform || "",
                      }}
                      onSave={handleEdit}
                      onCancel={() => setEditing(null)}
                    />
                  ) : (
                    <div className={cn(
                      "flex items-center gap-3 p-3 rounded-xl border border-border bg-card hover:bg-muted/30 transition-colors",
                      !s.is_visible && "opacity-50"
                    )}>
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-rose-400 to-pink-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0 overflow-hidden shadow-sm">
                        {s.avatar_url
                          ? <img src={s.avatar_url} alt="" className="w-full h-full object-cover" />
                          : <span>{(s.is_anonymous ? "?" : s.name).charAt(0).toUpperCase()}</span>
                        }
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-sm font-medium truncate">{s.is_anonymous ? `${s.name}（匿名）` : s.name}</span>
                          {s.platform && <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{s.platform}</span>}
                          {!s.is_visible && <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">已隐藏</span>}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                          {s.amount && <span className="text-rose-500 font-medium">{CURRENCY_SYMBOL[s.currency] || s.currency}{parseFloat(s.amount).toFixed(0)}</span>}
                          {s.sponsor_date && <span>{s.sponsor_date.slice(0, 10)}</span>}
                          {s.message && <span className="truncate max-w-[160px]">"{s.message}"</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <button
                          onClick={() => toggleVisible(s)}
                          className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                          title={s.is_visible ? "隐藏" : "显示"}
                        >
                          {s.is_visible ? <RiEyeLine className="w-3.5 h-3.5" /> : <RiEyeOffLine className="w-3.5 h-3.5" />}
                        </button>
                        <button
                          onClick={() => { setEditing(s); setShowForm(false); }}
                          className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                        >
                          <RiEditLine className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(s.id, s.name)}
                          disabled={deleting === s.id}
                          className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors text-muted-foreground hover:text-red-500"
                        >
                          {deleting === s.id ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AdminLayout>
  );
}
