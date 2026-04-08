import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated } from "@/lib/site-settings";
import {
  RiLoader4Line, RiCheckLine, RiToggleLine, RiToggleFill,
  RiGlobalLine, RiShieldCheckLine, RiSettings4Line,
  RiHomeLine, RiMailLine, RiBarChartLine, RiLockLine,
  RiMoneyDollarCircleLine, RiBankCardLine, RiImageLine,
  RiEyeLine, RiEyeOffLine, RiSaveLine, RiRefreshLine,
  RiCodeBoxLine, RiBellLine, RiUserLine, RiLinksLine,
  RiPaletteLine, RiSendPlane2Line, RiAlertLine, RiInformationLine,
  RiAddLine, RiDeleteBinLine, RiSearchLine,
} from "@remixicon/react";

type TabKey =
  | "branding"
  | "access"
  | "features"
  | "analytics"
  | "captcha"
  | "email"
  | "payment";

const TABS: { key: TabKey; label: string; icon: React.ElementType }[] = [
  { key: "branding",  label: "外观与首页", icon: RiPaletteLine },
  { key: "access",    label: "访问控制",   icon: RiLockLine },
  { key: "features",  label: "功能开关",   icon: RiSettings4Line },
  { key: "analytics", label: "统计分析",   icon: RiBarChartLine },
  { key: "captcha",   label: "验证码",     icon: RiShieldCheckLine },
  { key: "email",     label: "邮件配置",   icon: RiMailLine },
  { key: "payment",   label: "支付配置",   icon: RiBankCardLine },
];

// ── Effect-location badge — shows admins where a setting takes effect ─────────
type EffectScope = "全站" | "首页" | "结果页" | "SEO" | "社交分享" | "后台" | "顶部公告";
const EFFECT_COLORS: Record<EffectScope, string> = {
  "全站":   "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 border-blue-200/60 dark:border-blue-800/40",
  "首页":   "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200/60 dark:border-emerald-800/40",
  "结果页": "bg-purple-100 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400 border-purple-200/60 dark:border-purple-800/40",
  "SEO":    "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 border-orange-200/60 dark:border-orange-800/40",
  "社交分享":"bg-cyan-100 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-400 border-cyan-200/60 dark:border-cyan-800/40",
  "后台":   "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 border-red-200/60 dark:border-red-800/40",
  "顶部公告":"bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200/60 dark:border-amber-800/40",
};
function EffectBadge({ scope }: { scope: EffectScope }) {
  return (
    <span className={cn(
      "inline-flex items-center px-1.5 py-0.5 rounded-md text-[9px] font-semibold border shrink-0 tracking-wide",
      EFFECT_COLORS[scope],
    )}>
      {scope}
    </span>
  );
}

function SectionTitle({
  icon: Icon, title, desc, effect,
}: { icon: React.ElementType; title: string; desc?: string; effect?: EffectScope }) {
  return (
    <div className="flex items-start gap-3 mb-5">
      <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 mt-0.5">
        <Icon className="w-4 h-4 text-primary" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <h3 className="text-sm font-bold">{title}</h3>
          {effect && <EffectBadge scope={effect} />}
        </div>
        {desc && <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>}
      </div>
    </div>
  );
}

function Field({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs font-semibold text-foreground">{label}</Label>
      {desc && <p className="text-[11px] text-muted-foreground -mt-0.5">{desc}</p>}
      {children}
    </div>
  );
}

function Toggle({
  label, desc, checked, onChange,
}: { label: string; desc?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="w-full flex items-center justify-between gap-3 p-3 rounded-xl border border-border hover:bg-muted/50 transition-all group"
    >
      <div className="text-left min-w-0">
        <p className="text-xs font-semibold">{label}</p>
        {desc && <p className="text-[11px] text-muted-foreground mt-0.5 line-clamp-2">{desc}</p>}
      </div>
      {checked
        ? <RiToggleFill className="w-8 h-8 text-primary shrink-0" />
        : <RiToggleLine className="w-8 h-8 text-muted-foreground/40 shrink-0" />}
    </button>
  );
}

function PasswordField({ label, desc, value, onChange, placeholder }: {
  label: string; desc?: string; value: string;
  onChange: (v: string) => void; placeholder?: string;
}) {
  const [show, setShow] = React.useState(false);
  return (
    <Field label={label} desc={desc}>
      <div className="relative">
        <Input
          type={show ? "text" : "password"}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder || "留空表示未配置"}
          className="text-xs pr-9"
        />
        <button
          type="button"
          onClick={() => setShow(v => !v)}
          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
        >
          {show ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
        </button>
      </div>
    </Field>
  );
}

function TextareaField({ label, desc, value, onChange, rows = 3, placeholder }: {
  label: string; desc?: string; value: string;
  onChange: (v: string) => void; rows?: number; placeholder?: string;
}) {
  return (
    <Field label={label} desc={desc}>
      <textarea
        value={value}
        onChange={e => onChange(e.target.value)}
        rows={rows}
        placeholder={placeholder}
        className="w-full rounded-lg border border-input bg-background px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground resize-y min-h-[80px] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      />
    </Field>
  );
}

type RichItem = { text: string; color?: string; size?: "xs" | "sm" | "base"; bold?: boolean };
function parseRichItems(raw: string): RichItem[] {
  const trimmed = (raw || "").trim();
  if (trimmed.startsWith("[")) {
    try {
      const p = JSON.parse(trimmed);
      if (Array.isArray(p)) {
        const r = p.filter((i: unknown) => i && typeof (i as RichItem).text === "string");
        if (r.length > 0) return r as RichItem[];
      }
    } catch {}
  }
  const parts = trimmed.split("|").map(s => s.trim()).filter(Boolean);
  return parts.length > 0 ? parts.map(t => ({ text: t })) : [{ text: "" }];
}

function MultiItemInput({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  const [items, setItems] = React.useState<RichItem[]>(() => parseRichItems(value));
  const prevVal = React.useRef(value);

  React.useEffect(() => {
    if (value === prevVal.current) return;
    prevVal.current = value;
    setItems(parseRichItems(value));
  }, [value]);

  const propagate = (next: RichItem[]) => {
    setItems(next);
    const hasRich = next.some(i => i.color || i.size || i.bold);
    const nonEmpty = next.filter(i => i.text.trim());
    if (hasRich) {
      onChange(nonEmpty.length > 0 ? JSON.stringify(nonEmpty) : "");
    } else {
      onChange(nonEmpty.map(i => i.text).join(" | "));
    }
  };

  const update = (idx: number, field: keyof RichItem, v: string | boolean | undefined) => {
    const n = [...items];
    n[idx] = { ...n[idx], [field]: v };
    propagate(n);
  };
  const add = () => propagate([...items, { text: "" }]);
  const remove = (idx: number) => {
    const n = items.filter((_, i) => i !== idx);
    propagate(n.length ? n : [{ text: "" }]);
  };

  return (
    <div className="space-y-2">
      {items.map((item, idx) => (
        <div key={idx} className="space-y-1">
          <div className="flex items-center gap-1.5">
            {/* Row number */}
            <div className="w-6 h-6 rounded-md border border-border/60 bg-muted/30 flex items-center justify-center text-[10px] font-bold text-muted-foreground shrink-0 tabular-nums select-none">
              {idx + 1}
            </div>

            {/* Text input */}
            <Input
              value={item.text}
              onChange={e => update(idx, "text", e.target.value)}
              placeholder={placeholder}
              className="text-xs flex-1"
              style={{
                color: item.color || undefined,
                fontWeight: item.bold ? "700" : undefined,
                fontSize: item.size === "xs" ? "11px" : item.size === "base" ? "14px" : undefined,
              }}
            />

            {/* Color swatch — click to open native color picker */}
            <label className="relative shrink-0 cursor-pointer" title="文字颜色">
              <div
                className="w-6 h-6 rounded-md border border-border/60 overflow-hidden flex items-center justify-center"
                style={{ background: item.color ? item.color + "33" : undefined }}
              >
                <RiPaletteLine
                  className="w-3.5 h-3.5 transition-colors"
                  style={{ color: item.color || "currentColor", opacity: item.color ? 1 : 0.4 }}
                />
              </div>
              <input
                type="color"
                value={item.color || "#888888"}
                onChange={e => update(idx, "color", e.target.value)}
                className="absolute inset-0 opacity-0 w-full h-full cursor-pointer"
              />
            </label>

            {/* Clear color */}
            {item.color && (
              <button
                type="button"
                onClick={() => update(idx, "color", undefined)}
                title="清除颜色"
                className="w-5 h-5 rounded border border-border/50 text-muted-foreground/60 hover:text-destructive hover:border-destructive/40 flex items-center justify-center text-xs transition-colors shrink-0"
              >×</button>
            )}

            {/* Size selector */}
            <select
              value={item.size || "sm"}
              onChange={e => update(idx, "size", e.target.value as "xs" | "sm" | "base")}
              title="字体大小"
              className="h-6 text-[10px] rounded-md border border-border/60 bg-background px-1 shrink-0 text-muted-foreground"
            >
              <option value="xs">小</option>
              <option value="sm">中</option>
              <option value="base">大</option>
            </select>

            {/* Bold toggle */}
            <button
              type="button"
              onClick={() => update(idx, "bold", !item.bold)}
              title="粗体"
              className={`w-6 h-6 rounded-md border text-xs font-bold shrink-0 transition-colors ${item.bold ? "bg-foreground text-background border-foreground" : "border-border/60 text-muted-foreground hover:border-border"}`}
            >B</button>

            {/* Delete */}
            <button
              type="button"
              onClick={() => remove(idx)}
              disabled={items.length === 1 && !items[0].text}
              className="p-1.5 rounded-lg hover:bg-destructive/10 transition-colors text-muted-foreground hover:text-destructive disabled:opacity-30 disabled:pointer-events-none shrink-0"
            >
              <RiDeleteBinLine className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      ))}

      <button
        type="button"
        onClick={add}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1.5 rounded-lg hover:bg-muted/50"
      >
        <RiAddLine className="w-3.5 h-3.5" />
        添加一条
      </button>
      {items.filter(i => i.text).length > 1 && (
        <p className="text-[10px] text-muted-foreground/50 pl-8">多条内容将自动循环淡入淡出展示，每条可单独设置颜色、字号和粗体</p>
      )}
    </div>
  );
}

function SelectField({ label, desc, value, onChange, options }: {
  label: string; desc?: string; value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <Field label={label} desc={desc}>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full rounded-lg border border-input bg-background px-3 py-2 text-xs text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </Field>
  );
}

function BrandingTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  return (
    <div className="space-y-6">

      {/* ── 站点基本信息 ──────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiGlobalLine}
          title="站点基本信息"
          effect="全站"
          desc="导航栏 Logo、浏览器标签页标题、页脚版权文字，保存后立即全站生效"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="Logo 文字" desc="显示在导航栏左上角">
            <Input value={s.site_logo_text} onChange={e => set("site_logo_text", e.target.value)} placeholder="X.RW" className="text-xs" />
          </Field>
          <Field label="站点标题" desc="浏览器标签页 / SEO title">
            <Input value={s.site_title} onChange={e => set("site_title", e.target.value)} placeholder="X.RW · RDAP+WHOIS" className="text-xs" />
          </Field>
          <Field label="站点副标题" desc="首页 Logo 下方小字 & 导航栏 tagline">
            <Input value={s.site_subtitle} onChange={e => set("site_subtitle", e.target.value)} placeholder="专业的 WHOIS / RDAP 查询工具" className="text-xs" />
          </Field>
          <Field label="Favicon 图标 URL" desc="浏览器标签页图标（建议 32×32 PNG 或 SVG）">
            <Input value={s.site_icon_url} onChange={e => set("site_icon_url", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
        </div>
        <Field label="页脚文字" desc="显示在所有页面底部（© 版权行）">
          <Input value={s.site_footer} onChange={e => set("site_footer", e.target.value)} placeholder="© 2026 X.RW · WHOIS & RDAP Lookup Service" className="text-xs" />
        </Field>
      </div>

      {/* ── 首页 Hero ────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiHomeLine}
          title="首页 Hero 区域"
          effect="首页"
          desc="首页居中展示的大标题、副标题和搜索框占位文字，保存后首页刷新即生效"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="主标题" desc="首页居中大字（留空则使用 Logo 文字）">
            <Input value={s.home_hero_title} onChange={e => set("home_hero_title", e.target.value)} placeholder="（默认使用 Logo 文字）" className="text-xs" />
          </Field>
          <Field label="副标题" desc="主标题下方小字（留空则使用站点副标题）">
            <Input value={s.home_hero_subtitle} onChange={e => set("home_hero_subtitle", e.target.value)} placeholder="（默认使用站点副标题）" className="text-xs" />
          </Field>
          <Field label="搜索框占位文字" desc="搜索框内的提示文字">
            <Input value={s.home_placeholder} onChange={e => set("home_placeholder", e.target.value)} placeholder="搜索域名、IPv4、IPv6、ASN 或 CIDR" className="text-xs" />
          </Field>
        </div>
        <Toggle
          label="显示查询统计数字"
          desc="在首页搜索框下方显示总查询次数和今日查询次数"
          checked={s.home_show_stats === "1"}
          onChange={v => set("home_show_stats", v ? "1" : "")}
        />
      </div>

      {/* ── 顶部公告 ─────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiBellLine}
          title="顶部公告横幅"
          effect="顶部公告"
          desc="显示在所有页面最顶部的公告栏，用户可手动关闭；首页专属公告仅在首页展示"
        />
        <Field label="全局公告文字" desc="显示在所有页面顶部（非首页），留空则不显示">
          <Input value={s.site_announcement} onChange={e => set("site_announcement", e.target.value)} placeholder="全站公告内容，留空不显示…" className="text-xs" />
        </Field>
        <div className="border-t border-border/40 pt-4 space-y-4">
          <p className="text-[11px] text-muted-foreground font-medium">首页专属公告（仅在首页显示，用户关闭后记住状态）</p>
          <Toggle
            label="启用首页专属公告"
            checked={s.home_announcement_enabled === "1"}
            onChange={v => set("home_announcement_enabled", v ? "1" : "")}
          />
          <Field label="首页公告内容" desc="支持多条，用 | 分隔，自动循环淡入淡出播放">
            <MultiItemInput
              value={s.home_announcement_text}
              onChange={v => set("home_announcement_text", v)}
              placeholder="首页公告文字，多条用 | 分隔…"
            />
          </Field>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <SelectField
              label="公告类型"
              value={s.home_announcement_type}
              onChange={v => set("home_announcement_type", v)}
              options={[
                { value: "info",    label: "info — 蓝色信息" },
                { value: "success", label: "success — 绿色成功" },
                { value: "warning", label: "warning — 黄色警告" },
                { value: "error",   label: "error — 红色错误" },
              ]}
            />
            <Field label="公告点击跳转链接（可选）" desc="点击公告文字时跳转的 URL">
              <Input value={s.home_announcement_url} onChange={e => set("home_announcement_url", e.target.value)} placeholder="https://..." className="text-xs" />
            </Field>
          </div>
        </div>
      </div>

      {/* ── 结果页推广 ───────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiLinksLine}
          title="结果页推广条"
          effect="结果页"
          desc="在域名 WHOIS 查询结果页底部显示推广文字/广告链接，保存后结果页刷新即生效"
        />
        <Toggle
          label="启用结果页推广条"
          checked={s.result_ad_enabled === "1"}
          onChange={v => set("result_ad_enabled", v ? "1" : "")}
        />
        <Field label="推广文字" desc="支持多条，用 | 分隔，自动循环展示">
          <MultiItemInput
            value={s.result_ad_text}
            onChange={v => set("result_ad_text", v)}
            placeholder="推广/广告文字，多条用 | 分隔…"
          />
        </Field>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="点击跳转链接" desc="点击推广条时跳转的 URL">
            <Input value={s.result_ad_url} onChange={e => set("result_ad_url", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
          <Field label="推广标签文字" desc="显示在推广条最左侧的小标签">
            <Input value={s.result_ad_label} onChange={e => set("result_ad_label", e.target.value)} placeholder="广告" className="text-xs" />
          </Field>
        </div>
      </div>

      {/* ── SEO ──────────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiSearchLine}
          title="SEO / 搜索引擎优化"
          effect="SEO"
          desc="搜索引擎抓取时使用的描述和关键词，影响搜索结果排名和摘要展示"
        />
        <TextareaField
          label="站点描述"
          desc="浏览器收藏夹提示 & 搜索结果摘要（建议 80–160 字符）"
          value={s.site_description}
          onChange={v => set("site_description", v)}
          placeholder="快速查询域名、IP、ASN 的 WHOIS / RDAP 信息..."
        />
        <Field label="关键词" desc="用于 meta keywords，逗号分隔（对现代搜索引擎影响较小）">
          <Input value={s.site_keywords} onChange={e => set("site_keywords", e.target.value)} placeholder="Whois, RDAP, Domain Lookup..." className="text-xs" />
        </Field>
      </div>

      {/* ── 社交分享 ─────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiImageLine}
          title="社交媒体分享"
          effect="社交分享"
          desc="在微信、Twitter/X、Facebook 等平台分享链接时显示的预览卡片信息"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="站点名称" desc="分享卡片上显示的站点名">
            <Input value={s.og_site_name} onChange={e => set("og_site_name", e.target.value)} placeholder="X.RW" className="text-xs" />
          </Field>
          <Field label="站点 URL" desc="分享卡片的链接地址（影响 canonical URL）">
            <Input value={s.og_url} onChange={e => set("og_url", e.target.value)} placeholder="https://x.rw" className="text-xs" />
          </Field>
          <Field label="默认封面图" desc="未指定平台时使用的分享封面（OG image）">
            <Input value={s.og_image} onChange={e => set("og_image", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
          <Field label="Twitter/X 封面图" desc="Twitter Card 专用封面图">
            <Input value={s.og_image_twitter} onChange={e => set("og_image_twitter", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
          <Field label="微信封面图" desc="微信分享链接卡片专用封面图">
            <Input value={s.og_image_wechat} onChange={e => set("og_image_wechat", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
          <Field label="Facebook 封面图" desc="Facebook 分享卡片专用封面图">
            <Input value={s.og_image_facebook} onChange={e => set("og_image_facebook", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
        </div>
        <SelectField
          label="Twitter Card 样式"
          value={s.twitter_card}
          onChange={v => set("twitter_card", v)}
          options={[
            { value: "summary", label: "summary — 小图标卡片" },
            { value: "summary_large_image", label: "summary_large_image — 大图卡片（推荐）" },
          ]}
        />
      </div>

      {/* ── 管理员 ───────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiUserLine}
          title="管理员账号"
          effect="后台"
          desc="具有后台管理权限的邮箱，修改后需使用新邮箱重新登录"
        />
        <Field label="管理员邮箱" desc="修改后当前 session 仍然有效，下次登录或重新登录时生效">
          <Input value={s.admin_email} onChange={e => set("admin_email", e.target.value)} placeholder="admin@example.com" type="email" className="text-xs" />
        </Field>
      </div>

    </div>
  );
}

function AccessTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  return (
    <div className="space-y-6">
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiUserLine} title="注册与登录" desc="控制用户注册和访问方式" />
        <Toggle
          label="开放注册"
          desc="允许新用户通过邮箱注册账号"
          checked={s.allow_registration === "1"}
          onChange={v => set("allow_registration", v ? "1" : "")}
        />
        <Toggle
          label="需要邀请码注册"
          desc="开启后注册时需要填写有效的邀请码"
          checked={s.require_invite_code === "1"}
          onChange={v => set("require_invite_code", v ? "1" : "")}
        />
        <Toggle
          label="登录后才能查询"
          desc="未登录用户无法进行任何查询"
          checked={s.require_login === "1"}
          onChange={v => set("require_login", v ? "1" : "")}
        />
        <Toggle
          label="禁用登录入口"
          desc="隐藏登录按钮，阻止用户登录（已登录用户不受影响）"
          checked={s.disable_login === "1"}
          onChange={v => set("disable_login", v ? "1" : "")}
        />
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiLockLine} title="站点状态" desc="紧急管控与维护模式" />
        <Toggle
          label="维护模式"
          desc="开启后所有访问者将看到维护提示页面"
          checked={s.maintenance_mode === "1"}
          onChange={v => set("maintenance_mode", v ? "1" : "")}
        />
        <Field label="维护提示文字" desc="维护模式下显示给访问者的说明文字">
          <Input value={s.maintenance_message} onChange={e => set("maintenance_message", e.target.value)} placeholder="站点维护中，请稍后再来..." className="text-xs" />
        </Field>
        <Toggle
          label="只读查询模式"
          desc="开启后用户只能进行查询，无法使用任何需要写入的功能（注册、订阅等）"
          checked={s.query_only_mode === "1"}
          onChange={v => set("query_only_mode", v ? "1" : "")}
        />
        <Toggle
          label="隐藏原始 WHOIS"
          desc="在查询结果页隐藏原始 WHOIS 文本，只显示结构化数据"
          checked={s.hide_raw_whois === "1"}
          onChange={v => set("hide_raw_whois", v ? "1" : "")}
        />
      </div>
    </div>
  );
}

function FeaturesTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  const FEATURES: { key: keyof SiteSettings; label: string; desc: string }[] = [
    { key: "enable_search_links",  label: "查询结果外链",    desc: "在查询结果页显示跳转到注册商等外部链接" },
    { key: "enable_feedback",      label: "用户反馈",        desc: "允许用户在查询结果页提交反馈报告" },
    { key: "enable_stamps",        label: "品牌徽章 (Stamps)", desc: "开启域名所有权认证徽章功能" },
    { key: "enable_sponsor",       label: "赞助页面",        desc: "在导航中显示赞助/打赏入口" },
    { key: "enable_share",         label: "分享功能",        desc: "在查询结果页显示分享按钮" },
    { key: "enable_dns",           label: "DNS 查询",        desc: "在结果页显示 DNS 记录标签页" },
    { key: "enable_ip",            label: "IP 地理定位",     desc: "在结果页显示 IP 地理信息" },
    { key: "enable_ssl",           label: "SSL 证书检测",    desc: "在结果页显示 SSL 证书信息" },
    { key: "enable_icp",           label: "ICP 备案查询",    desc: "在结果页显示 ICP 备案信息" },
    { key: "enable_http",          label: "HTTP 状态检测",   desc: "在结果页显示网站 HTTP 状态" },
    { key: "enable_tools",         label: "工具页面",        desc: "在导航中显示在线工具入口" },
    { key: "enable_remind",        label: "域名到期提醒",    desc: "允许用户设置域名到期邮件提醒" },
    { key: "enable_links",         label: "友情链接页面",    desc: "在导航中显示友情链接页面" },
    { key: "enable_about",         label: "关于页面",        desc: "在导航中显示关于/介绍页面" },
    { key: "enable_changelog",     label: "更新日志页面",    desc: "在导航中显示版本更新日志" },
    { key: "enable_docs",          label: "文档/API 页面",   desc: "在导航中显示 API 文档入口" },
  ];

  return (
    <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
      <SectionTitle icon={RiSettings4Line} title="功能模块开关" desc="按需开启或关闭各功能模块" />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {FEATURES.map(f => (
          <Toggle
            key={f.key}
            label={f.label}
            desc={f.desc}
            checked={s[f.key] === "1"}
            onChange={v => set(f.key, v ? "1" : "")}
          />
        ))}
      </div>
    </div>
  );
}

function AnalyticsTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  return (
    <div className="space-y-6">
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiBarChartLine} title="统计分析" desc="集成第三方统计服务" />
        <Field label="Google Analytics ID" desc="格式：G-XXXXXXXXXX">
          <Input value={s.analytics_google} onChange={e => set("analytics_google", e.target.value)} placeholder="G-XXXXXXXXXX" className="text-xs" />
        </Field>
        <Field label="Umami Website ID">
          <Input value={s.analytics_umami} onChange={e => set("analytics_umami", e.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" className="text-xs" />
        </Field>
        <Field label="Umami Script URL" desc="自托管 Umami 的脚本地址">
          <Input value={s.analytics_umami_src} onChange={e => set("analytics_umami_src", e.target.value)} placeholder="https://umami.yourdomain.com/script.js" className="text-xs" />
        </Field>
      </div>
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiCodeBoxLine} title="自定义 Head 脚本" desc="会被注入到每个页面 <head> 中的自定义代码（请谨慎填写）" />
        <TextareaField
          label="自定义脚本"
          desc='支持 <script>、<link>、<meta> 等任何 HTML 标签'
          value={s.custom_head_script}
          onChange={v => set("custom_head_script", v)}
          rows={5}
          placeholder='<script>/* 自定义代码 */</script>'
        />
      </div>
    </div>
  );
}

function CaptchaTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  const provider = s.captcha_provider;
  const isEnabled = !!provider;
  const onLogin = (s.captcha_on_login ?? "1") !== "";
  const onRegister = (s.captcha_on_register ?? "1") !== "";

  return (
    <div className="space-y-6">
      {/* Status banner */}
      <div className={cn(
        "flex items-center gap-3 px-4 py-3 rounded-xl border text-sm font-medium",
        isEnabled
          ? "bg-emerald-50/60 dark:bg-emerald-950/20 border-emerald-200/60 dark:border-emerald-700/30 text-emerald-700 dark:text-emerald-300"
          : "bg-muted/60 border-border text-muted-foreground"
      )}>
        <RiShieldCheckLine className={cn("w-4 h-4 shrink-0", isEnabled ? "text-emerald-500" : "text-muted-foreground/50")} />
        <div className="flex-1 min-w-0">
          <span className="font-bold">{isEnabled ? "验证码已启用" : "验证码未启用"}</span>
          {isEnabled && <span className="text-xs ml-2 opacity-70">当前提供商：{provider}</span>}
        </div>
        <span className={cn(
          "text-[11px] px-2 py-0.5 rounded-full font-bold",
          isEnabled ? "bg-emerald-500 text-white" : "bg-muted-foreground/20 text-muted-foreground"
        )}>{isEnabled ? "ON" : "OFF"}</span>
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiShieldCheckLine} title="验证码提供商" desc={'选择用于防止机器人的验证码服务，选择"不启用"则关闭所有验证'} />
        <SelectField
          label="验证码提供商"
          value={provider}
          onChange={v => set("captcha_provider", v)}
          options={[
            { value: "",             label: "不启用验证码" },
            { value: "turnstile",    label: "Cloudflare Turnstile（推荐）" },
            { value: "hcaptcha",     label: "hCaptcha" },
            { value: "mtcaptcha",    label: "MTCaptcha" },
          ]}
        />
      </div>

      {/* Scope toggles — only shown when CAPTCHA is enabled */}
      {isEnabled && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="验证码生效范围" desc="控制哪些操作需要通过验证码验证" />
          <Toggle
            label="登录时验证"
            desc="用户登录时需通过人机验证"
            checked={onLogin}
            onChange={v => set("captcha_on_login", v ? "1" : "")}
          />
          <Toggle
            label="注册时验证"
            desc="新用户注册时需通过人机验证"
            checked={onRegister}
            onChange={v => set("captcha_on_register", v ? "1" : "")}
          />
        </div>
      )}

      {provider === "turnstile" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="Cloudflare Turnstile" />
          <Field label="Site Key">
            <Input value={s.captcha_turnstile_site_key} onChange={e => set("captcha_turnstile_site_key", e.target.value)} placeholder="0x..." className="text-xs" />
          </Field>
          <PasswordField label="Secret Key" value={s.captcha_turnstile_secret_key} onChange={v => set("captcha_turnstile_secret_key", v)} />
        </div>
      )}

      {provider === "hcaptcha" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="hCaptcha" />
          <Field label="Site Key">
            <Input value={s.captcha_hcaptcha_site_key} onChange={e => set("captcha_hcaptcha_site_key", e.target.value)} placeholder="your-site-key" className="text-xs" />
          </Field>
          <PasswordField label="Secret Key" value={s.captcha_hcaptcha_secret_key} onChange={v => set("captcha_hcaptcha_secret_key", v)} />
        </div>
      )}

      {provider === "mtcaptcha" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="MTCaptcha" />
          <Field label="Site Key">
            <Input value={s.captcha_mtcaptcha_site_key} onChange={e => set("captcha_mtcaptcha_site_key", e.target.value)} placeholder="MTPublic-..." className="text-xs" />
          </Field>
          <PasswordField label="Secret Key" value={s.captcha_mtcaptcha_secret_key} onChange={v => set("captcha_mtcaptcha_secret_key", v)} />
        </div>
      )}
    </div>
  );
}

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

function EmailTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  const [configStatus, setConfigStatus] = React.useState<EmailConfigStatus | null>(null);
  const [checking, setChecking] = React.useState(false);
  const [testTo, setTestTo] = React.useState("");
  const [testing, setTesting] = React.useState(false);
  const [testResults, setTestResults] = React.useState<TestEmailResult[] | null>(null);

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
    <div className="space-y-6">
      {/* Config status panel */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <SectionTitle icon={RiMailLine} title="邮件发送状态" desc="当前邮件服务配置诊断" />
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

        {/* Send test email */}
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
        <SectionTitle icon={RiMailLine} title="SMTP 邮件配置" desc="用于发送注册验证、密码重置等系统邮件" />
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
            <Input value={s.smtp_from} onChange={e => set("smtp_from", e.target.value)} placeholder="X.RW <noreply@example.com>" className="text-xs" />
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
        <SectionTitle icon={RiMailLine} title="Resend 邮件配置" desc="使用 Resend 服务发送邮件（与 SMTP 二选一）" />
        <PasswordField label="Resend API Key" desc="从 resend.com 后台获取" value={s.resend_api_key} onChange={v => set("resend_api_key", v)} placeholder="re_..." />
        <Field label="发件人地址">
          <Input value={s.resend_from_email} onChange={e => set("resend_from_email", e.target.value)} placeholder="X.RW <noreply@example.com>" className="text-xs" />
        </Field>
      </div>
    </div>
  );
}

function PaymentTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  return (
    <div className="space-y-6">
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiMoneyDollarCircleLine} title="通用支付设置" />
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
        <SectionTitle icon={RiBankCardLine} title="Stripe" />
        <Toggle label="启用 Stripe 支付" checked={s.payment_stripe_enabled === "1"} onChange={v => set("payment_stripe_enabled", v ? "1" : "")} />
        <Field label="Publishable Key (pk_)">
          <Input value={s.payment_stripe_pk} onChange={e => set("payment_stripe_pk", e.target.value)} placeholder="pk_live_..." className="text-xs" />
        </Field>
        <PasswordField label="Secret Key (sk_)" value={s.payment_stripe_sk} onChange={v => set("payment_stripe_sk", v)} placeholder="sk_live_..." />
        <PasswordField label="Webhook Secret" value={s.payment_stripe_webhook_secret} onChange={v => set("payment_stripe_webhook_secret", v)} placeholder="whsec_..." />
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiBankCardLine} title="PayPal" />
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
        <SectionTitle icon={RiBankCardLine} title="虎皮椒 (XunhuPay · 支付宝渠道)" />
        <Toggle label="启用虎皮椒支付宝" checked={s.payment_xunhupay_enabled === "1"} onChange={v => set("payment_xunhupay_enabled", v ? "1" : "")} />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="AppID">
            <Input value={s.payment_xunhupay_appid} onChange={e => set("payment_xunhupay_appid", e.target.value)} placeholder="AppID" className="text-xs" />
          </Field>
          <PasswordField label="AppSecret" value={s.payment_xunhupay_secret} onChange={v => set("payment_xunhupay_secret", v)} />
        </div>
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiBankCardLine} title="微信支付 (WeChat Pay · 虎皮椒网关)" />
        <Toggle label="启用微信支付" checked={s.payment_wechat_enabled === "1"} onChange={v => set("payment_wechat_enabled", v ? "1" : "")} />
        <p className="text-xs text-muted-foreground">微信支付通过虎皮椒网关处理，复用上方配置的虎皮椒 AppID 和 AppSecret，无需重复填写。启用前请确保虎皮椒账户已开通微信支付渠道。</p>
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiBankCardLine} title="支付宝 (Alipay)" />
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
  );
}

export default function AdminSettingsPage() {
  const [settings, setSettings] = React.useState<SiteSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [dirty, setDirty] = React.useState(false);
  const [tab, setTab] = React.useState<TabKey>("branding");

  React.useEffect(() => {
    setLoading(true);
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(data => {
        if (data.settings) {
          setSettings({ ...DEFAULT_SETTINGS, ...data.settings });
        }
      })
      .catch(() => toast.error("加载设置失败"))
      .finally(() => setLoading(false));
  }, []);

  function set(key: keyof SiteSettings, value: string) {
    setSettings(prev => ({ ...prev, [key]: value }));
    setDirty(true);
  }

  async function save() {
    setSaving(true);
    try {
      const res = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
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
        setSettings({ ...DEFAULT_SETTINGS, ...data.settings });
        setDirty(false);
        toast.success("已重新加载");
      }
    } catch {
      toast.error("加载失败");
    } finally {
      setLoading(false);
    }
  }

  const tabProps = { s: settings, set };

  return (
    <AdminLayout title="网站设置">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-lg font-bold">网站设置</h1>
          <p className="text-xs text-muted-foreground mt-0.5">管理站点品牌、功能开关、第三方服务集成等全局配置</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={reload} disabled={loading} className="gap-1.5 text-xs">
            <RiRefreshLine className={cn("w-3.5 h-3.5", loading && "animate-spin")} />
            刷新
          </Button>
          <Button size="sm" onClick={save} disabled={saving || loading || !dirty} className="gap-1.5 text-xs">
            {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
            {dirty ? "保存更改" : "已保存"}
          </Button>
        </div>
      </div>

      {/* Unsaved changes banner */}
      {dirty && (
        <div className="mb-4 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400">
          <RiCheckLine className="w-4 h-4 shrink-0" />
          <p className="text-xs font-medium">有未保存的更改，请记得点击「保存更改」</p>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap gap-1.5 mb-6 pb-4 border-b border-border">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all",
              tab === key
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-muted"
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <>
          {tab === "branding"  && <BrandingTab {...tabProps} />}
          {tab === "access"    && <AccessTab {...tabProps} />}
          {tab === "features"  && <FeaturesTab {...tabProps} />}
          {tab === "analytics" && <AnalyticsTab {...tabProps} />}
          {tab === "captcha"   && <CaptchaTab {...tabProps} />}
          {tab === "email"     && <EmailTab {...tabProps} />}
          {tab === "payment"   && <PaymentTab {...tabProps} />}
        </>
      )}

      {/* Sticky save footer */}
      {dirty && (
        <div className="sticky bottom-6 mt-8 flex justify-end">
          <Button onClick={save} disabled={saving} className="gap-2 shadow-lg">
            {saving ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSaveLine className="w-4 h-4" />}
            保存所有更改
          </Button>
        </div>
      )}
    </AdminLayout>
  );
}
