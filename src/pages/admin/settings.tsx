import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated } from "@/lib/site-settings";
import Link from "next/link";
import {
  RiLoader4Line, RiCheckLine, RiToggleLine, RiToggleFill,
  RiGlobalLine, RiShieldCheckLine, RiSettings4Line,
  RiHomeLine, RiMailLine, RiBarChartLine, RiLockLine,
  RiMoneyDollarCircleLine, RiBankCardLine, RiImageLine,
  RiEyeLine, RiEyeOffLine, RiSaveLine, RiRefreshLine,
  RiCodeBoxLine, RiBellLine, RiUserLine, RiLinksLine,
  RiPaletteLine, RiSendPlane2Line, RiAlertLine, RiInformationLine,
  RiAddLine, RiDeleteBinLine, RiSearchLine,
  // Feature icons
  RiExternalLinkLine, RiMessage3Line, RiMedalLine, RiHeartLine,
  RiShareLine, RiServerLine, RiMapPin2Line, RiFileList3Line,
  RiToolsLine, RiAlarmLine, RiHistoryLine, RiBook2Line,
  RiArrowRightLine, RiTimerLine, RiWifiLine, RiCalendarLine,
} from "@remixicon/react";

type TabKey =
  | "branding"
  | "access"
  | "features"
  | "analytics"
  | "email"
  | "payment";

const TABS: { key: TabKey; label: string; icon: React.ElementType }[] = [
  { key: "branding",  label: "外观与首页", icon: RiPaletteLine },
  { key: "access",    label: "安全防护",   icon: RiShieldCheckLine },
  { key: "features",  label: "功能开关",   icon: RiSettings4Line },
  { key: "analytics", label: "统计分析",   icon: RiBarChartLine },
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
          <Field label="主标题字号" desc="控制首页大标题的显示大小">
            <div className="flex gap-1.5 flex-wrap">
              {(["xs","sm","md","lg","xl"] as const).map(sz => {
                const labels: Record<string,string> = { xs:"极小", sm:"小", md:"中（默认）", lg:"大", xl:"超大" };
                const active = (s.home_hero_title_size || "md") === sz;
                return (
                  <button
                    key={sz}
                    type="button"
                    onClick={() => set("home_hero_title_size", sz === "md" ? "" : sz)}
                    className={cn("px-2.5 py-1 rounded-lg text-xs border transition-colors", active ? "bg-primary text-primary-foreground border-primary" : "border-border hover:border-primary/40 hover:bg-muted/50")}
                  >
                    {labels[sz]}
                  </button>
                );
              })}
            </div>
          </Field>
          <Field label="副标题字号" desc="控制首页副标题的显示大小">
            <div className="flex gap-1.5 flex-wrap">
              {(["xs","sm","md","lg"] as const).map(sz => {
                const labels: Record<string,string> = { xs:"极小（默认）", sm:"小", md:"中", lg:"大" };
                const active = (s.home_hero_subtitle_size || "xs") === sz;
                return (
                  <button
                    key={sz}
                    type="button"
                    onClick={() => set("home_hero_subtitle_size", sz === "xs" ? "" : sz)}
                    className={cn("px-2.5 py-1 rounded-lg text-xs border transition-colors", active ? "bg-primary text-primary-foreground border-primary" : "border-border hover:border-primary/40 hover:bg-muted/50")}
                  >
                    {labels[sz]}
                  </button>
                );
              })}
            </div>
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
          <div className="border-t border-border/40 pt-4 space-y-2">
            <div className="flex items-center gap-2">
              <RiTimerLine className="w-3.5 h-3.5 text-muted-foreground" />
              <p className="text-[11px] text-muted-foreground font-medium">倒计时模式（可选）</p>
            </div>
            <Field
              label="截止时间"
              desc="设置后公告旁边自动显示「距活动结束 X 小时 X 分」倒计时；过期后自动隐藏公告"
            >
              <Input
                type="datetime-local"
                value={s.home_announcement_deadline || ""}
                onChange={e => set("home_announcement_deadline", e.target.value)}
                className="text-xs"
              />
            </Field>
            {s.home_announcement_deadline && (() => {
              const deadline = new Date(s.home_announcement_deadline);
              const now = new Date();
              const diff = deadline.getTime() - now.getTime();
              if (diff <= 0) return (
                <p className="text-[11px] text-red-500">⚠️ 截止时间已过期，公告将自动隐藏</p>
              );
              const hours = Math.floor(diff / 3600000);
              const mins  = Math.floor((diff % 3600000) / 60000);
              return (
                <p className="text-[11px] text-emerald-600 dark:text-emerald-400">
                  ✓ 距截止还剩 {hours > 0 ? `${hours} 小时 ` : ""}{mins} 分钟
                </p>
              );
            })()}
          </div>
        </div>
      </div>

      {/* ── 结果页推广 ───────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiLinksLine}
          title="结果页推广条"
          effect="结果页"
          desc="在域名 WHOIS 查询结果页显示推广内容，支持纯文字、图片横幅、自定义 HTML 三种模式"
        />
        <Toggle
          label="启用结果页推广条"
          checked={s.result_ad_enabled === "1"}
          onChange={v => set("result_ad_enabled", v ? "1" : "")}
        />

        {s.result_ad_enabled === "1" && (
          <>
            <SelectField
              label="推广内容模式"
              value={s.result_ad_mode || "text"}
              onChange={v => set("result_ad_mode", v)}
              options={[
                { value: "text",  label: "纯文字 — 滚动文字条（支持多条轮播）" },
                { value: "image", label: "图片横幅 — 显示一张广告图片" },
                { value: "html",  label: "自定义 HTML — 嵌入任意 HTML 代码" },
              ]}
            />

            {/* text mode */}
            {(s.result_ad_mode || "text") === "text" && (
              <>
                <Field label="推广文字" desc="支持多条，自动循环轮播；可设置颜色、大小、加粗">
                  <MultiItemInput
                    value={s.result_ad_text}
                    onChange={v => set("result_ad_text", v)}
                    placeholder="推广/广告文字，多条用 | 分隔…"
                  />
                </Field>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <Field label="点击跳转链接" desc="点击推广条时跳转的 URL（可选）">
                    <Input value={s.result_ad_url} onChange={e => set("result_ad_url", e.target.value)} placeholder="https://..." className="text-xs" />
                  </Field>
                  <Field label="推广标签文字" desc="显示在左侧的小标签，如「广告」「推广」「合作」">
                    <Input value={s.result_ad_label} onChange={e => set("result_ad_label", e.target.value)} placeholder="广告" className="text-xs" />
                  </Field>
                </div>
              </>
            )}

            {/* image mode */}
            {s.result_ad_mode === "image" && (
              <>
                <Field label="图片 URL" desc="广告横幅图片地址（建议宽度 600–1200px，高度 60–120px 的长条图）">
                  <Input value={s.result_ad_image_url} onChange={e => set("result_ad_image_url", e.target.value)} placeholder="https://example.com/banner.png" className="text-xs" />
                </Field>
                {s.result_ad_image_url && (
                  <div className="rounded-xl border border-border/60 overflow-hidden bg-muted/30 p-2">
                    <p className="text-[10px] text-muted-foreground mb-2">预览：</p>
                    <img
                      src={s.result_ad_image_url}
                      alt={s.result_ad_image_alt || "广告预览"}
                      className="max-w-full max-h-28 object-contain rounded-lg mx-auto block"
                      onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
                    />
                  </div>
                )}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <Field label="图片 Alt 文字" desc="图片无法加载时显示的替代文字（同时用于 SEO）">
                    <Input value={s.result_ad_image_alt} onChange={e => set("result_ad_image_alt", e.target.value)} placeholder="广告" className="text-xs" />
                  </Field>
                  <Field label="点击跳转链接" desc="点击图片时跳转的 URL（可选）">
                    <Input value={s.result_ad_url} onChange={e => set("result_ad_url", e.target.value)} placeholder="https://..." className="text-xs" />
                  </Field>
                </div>
              </>
            )}

            {/* html mode */}
            {s.result_ad_mode === "html" && (
              <>
                <div className="flex items-start gap-2 px-3 py-2 rounded-xl bg-amber-500/8 border border-amber-500/20">
                  <RiAlertLine className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-amber-700 dark:text-amber-400">
                    HTML 模式会直接渲染代码，请确保内容来源可信。支持嵌入第三方广告脚本（如 Google AdSense、Carbon Ads 等）。
                  </p>
                </div>
                <TextareaField
                  label="自定义 HTML 代码"
                  desc="直接渲染到结果页推广区域，支持 <script>、<img>、<a> 等所有 HTML 标签"
                  value={s.result_ad_html}
                  onChange={v => set("result_ad_html", v)}
                  rows={6}
                  placeholder={'<!-- 示例：Google AdSense -->\n<ins class="adsbygoogle"\n  style="display:block"\n  data-ad-client="ca-pub-XXXXXXXX"\n  data-ad-slot="XXXXXXXX"\n  data-ad-format="auto"></ins>'}
                />
              </>
            )}
          </>
        )}
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

        {/* OG Card Live Preview */}
        {(() => {
          const customImg   = s.og_image_twitter || s.og_image || "";
          const previewImg  = customImg || "/api/og-image";
          const previewTitle = s.site_title || s.site_logo_text || "站点标题";
          const previewDesc  = s.site_description || "站点描述";
          const previewSite  = s.og_url ? s.og_url.replace(/^https?:\/\//, "").replace(/\/$/, "") : (s.og_site_name || "example.com");
          const isLarge = !s.twitter_card || s.twitter_card === "summary_large_image";

          return (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">实时预览 · Twitter/X 分享卡片</p>
                {!customImg && (
                  <span className="text-[10px] text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 border border-amber-200/60 dark:border-amber-700/40 rounded-full px-2 py-0.5 font-medium">
                    使用默认 OG 图
                  </span>
                )}
              </div>
              <div className="rounded-2xl border border-border/80 overflow-hidden bg-card max-w-sm shadow-sm">
                {isLarge ? (
                  <>
                    <div className="w-full h-36 bg-muted/40 overflow-hidden">
                      <img src={previewImg} alt="" className="w-full h-full object-cover" onError={e => { (e.target as HTMLImageElement).src = "/og-banner.png"; }} />
                    </div>
                    <div className="p-3 border-t border-border/60">
                      <p className="text-[10px] text-muted-foreground/60 uppercase tracking-wide truncate">{previewSite}</p>
                      <p className="text-xs font-semibold line-clamp-1 mt-0.5">{previewTitle}</p>
                      <p className="text-[10px] text-muted-foreground line-clamp-2 mt-0.5">{previewDesc}</p>
                    </div>
                  </>
                ) : (
                  <div className="flex items-stretch">
                    <div className="w-20 h-20 shrink-0 bg-muted/40 overflow-hidden">
                      <img src={previewImg} alt="" className="w-full h-full object-cover" onError={e => { (e.target as HTMLImageElement).src = "/og-banner.png"; }} />
                    </div>
                    <div className="p-2.5 flex flex-col justify-center min-w-0">
                      <p className="text-[11px] text-muted-foreground/60 truncate">{previewSite}</p>
                      <p className="text-xs font-semibold line-clamp-1 mt-0.5">{previewTitle}</p>
                      <p className="text-[10px] text-muted-foreground line-clamp-2 mt-0.5">{previewDesc}</p>
                    </div>
                  </div>
                )}
              </div>
              <p className="text-[10px] text-muted-foreground">修改下方字段后预览实时更新 · 留空时自动使用站点默认 OG 图</p>
            </div>
          );
        })()}

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
          <Field label="Twitter/X 封面图" desc="Twitter Card 专用封面图（预览使用此图）">
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
            { value: "summary", label: "summary — 小图标卡片（左图右文）" },
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
  const captchaProvider = s.captcha_provider;
  const captchaEnabled  = !!captchaProvider;
  const onLogin    = (s.captcha_on_login    ?? "1") !== "";
  const onRegister = (s.captcha_on_register ?? "1") !== "";

  return (
    <div className="space-y-6">

      {/* ── 注册与登录 ── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiUserLine} title="注册与登录" desc="控制用户注册方式和访问入口" />
        <Toggle label="开放注册" desc="允许新用户通过邮箱注册账号" checked={s.allow_registration === "1"} onChange={v => set("allow_registration", v ? "1" : "")} />
        <Toggle label="需要邀请码注册" desc="开启后注册时需要填写有效的邀请码" checked={s.require_invite_code === "1"} onChange={v => set("require_invite_code", v ? "1" : "")} />
        <Toggle label="登录后才能查询" desc="未登录用户无法进行任何查询" checked={s.require_login === "1"} onChange={v => set("require_login", v ? "1" : "")} />
        <Toggle label="禁用登录入口" desc="隐藏登录按钮，阻止用户登录（已登录用户不受影响）" checked={s.disable_login === "1"} onChange={v => set("disable_login", v ? "1" : "")} />
      </div>

      {/* ── 站点状态 ── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiLockLine} title="站点状态" desc="紧急管控与维护模式" />
        <Toggle label="维护模式" desc="开启后所有访问者将看到维护提示页面" checked={s.maintenance_mode === "1"} onChange={v => set("maintenance_mode", v ? "1" : "")} />
        <Field label="维护提示文字" desc="维护模式下显示给访问者的说明文字">
          <Input value={s.maintenance_message} onChange={e => set("maintenance_message", e.target.value)} placeholder="站点维护中，请稍后再来..." className="text-xs" />
        </Field>
        <Toggle label="只读查询模式" desc="开启后用户只能进行查询，无法使用任何需要写入的功能（注册、订阅等）" checked={s.query_only_mode === "1"} onChange={v => set("query_only_mode", v ? "1" : "")} />
        <Toggle label="隐藏原始 WHOIS" desc="在查询结果页隐藏原始 WHOIS 文本，只显示结构化数据" checked={s.hide_raw_whois === "1"} onChange={v => set("hide_raw_whois", v ? "1" : "")} />
      </div>

      {/* ── 验证码 ── */}
      <div className={cn(
        "flex items-center gap-3 px-4 py-3 rounded-xl border text-sm font-medium",
        captchaEnabled
          ? "bg-emerald-50/60 dark:bg-emerald-950/20 border-emerald-200/60 dark:border-emerald-700/30 text-emerald-700 dark:text-emerald-300"
          : "bg-muted/60 border-border text-muted-foreground"
      )}>
        <RiShieldCheckLine className={cn("w-4 h-4 shrink-0", captchaEnabled ? "text-emerald-500" : "text-muted-foreground/50")} />
        <div className="flex-1 min-w-0">
          <span className="font-bold">{captchaEnabled ? "验证码已启用" : "验证码未启用"}</span>
          {captchaEnabled && <span className="text-xs ml-2 opacity-70">当前提供商：{captchaProvider}</span>}
        </div>
        <span className={cn("text-[11px] px-2 py-0.5 rounded-full font-bold", captchaEnabled ? "bg-emerald-500 text-white" : "bg-muted-foreground/20 text-muted-foreground")}>
          {captchaEnabled ? "ON" : "OFF"}
        </span>
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiShieldCheckLine} title="人机验证 (CAPTCHA)" desc='防止机器人和恶意请求；选择"不启用"关闭所有验证' />
        <SelectField
          label="验证码提供商"
          value={captchaProvider}
          onChange={v => set("captcha_provider", v)}
          options={[
            { value: "",          label: "不启用验证码" },
            { value: "turnstile", label: "Cloudflare Turnstile（推荐，无感验证）" },
            { value: "hcaptcha",  label: "hCaptcha（隐私友好）" },
            { value: "mtcaptcha", label: "MTCaptcha" },
          ]}
        />

        {captchaEnabled && (
          <div className="space-y-3 pt-1 border-t border-border/40">
            <p className="text-[11px] text-muted-foreground font-medium pt-1">验证码生效范围</p>
            <Toggle label="登录时验证" desc="用户登录时需通过人机验证" checked={onLogin} onChange={v => set("captcha_on_login", v ? "1" : "")} />
            <Toggle label="注册时验证" desc="新用户注册时需通过人机验证" checked={onRegister} onChange={v => set("captcha_on_register", v ? "1" : "")} />
          </div>
        )}
      </div>

      {captchaProvider === "turnstile" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="Cloudflare Turnstile 密钥" desc="在 Cloudflare Dashboard → Turnstile 获取" />
          <Field label="Site Key（公开密钥）">
            <Input value={s.captcha_turnstile_site_key} onChange={e => set("captcha_turnstile_site_key", e.target.value)} placeholder="0x..." className="text-xs" />
          </Field>
          <PasswordField label="Secret Key（私密密钥）" value={s.captcha_turnstile_secret_key} onChange={v => set("captcha_turnstile_secret_key", v)} />
        </div>
      )}
      {captchaProvider === "hcaptcha" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="hCaptcha 密钥" desc="在 hcaptcha.com 后台获取" />
          <Field label="Site Key"><Input value={s.captcha_hcaptcha_site_key} onChange={e => set("captcha_hcaptcha_site_key", e.target.value)} placeholder="your-site-key" className="text-xs" /></Field>
          <PasswordField label="Secret Key" value={s.captcha_hcaptcha_secret_key} onChange={v => set("captcha_hcaptcha_secret_key", v)} />
        </div>
      )}
      {captchaProvider === "mtcaptcha" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="MTCaptcha 密钥" desc="在 mtcaptcha.com 后台获取" />
          <Field label="Site Key"><Input value={s.captcha_mtcaptcha_site_key} onChange={e => set("captcha_mtcaptcha_site_key", e.target.value)} placeholder="MTPublic-..." className="text-xs" /></Field>
          <PasswordField label="Secret Key" value={s.captcha_mtcaptcha_secret_key} onChange={v => set("captcha_mtcaptcha_secret_key", v)} />
        </div>
      )}
    </div>
  );
}

function FeaturesTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  type FeatureDef = {
    key: keyof SiteSettings;
    label: string;
    desc: string;
    icon: React.ElementType;
    adminLink?: string;
    adminLabel?: string;
    requires?: string; // note about dependencies
  };

  const RESULT_FEATURES: FeatureDef[] = [
    { key: "enable_search_links", label: "查询结果外链",     icon: RiExternalLinkLine, desc: "结果页显示跳转到注册商、Whois 查询等外部链接" },
    { key: "enable_feedback",     label: "用户反馈",         icon: RiMessage3Line,     desc: "用户可在结果页提交 WHOIS 数据错误反馈", adminLink: "/admin/feedback", adminLabel: "查看反馈" },
    { key: "enable_stamps",       label: "品牌徽章",         icon: RiMedalLine,        desc: "域名所有者可申请认证徽章（Stamps）", adminLink: "/admin/stamps", adminLabel: "管理徽章" },
    { key: "enable_share",        label: "结果分享",         icon: RiShareLine,        desc: "结果页显示分享按钮，支持链接复制和社交分享" },
    { key: "enable_dns",          label: "DNS 查询",         icon: RiServerLine,       desc: "结果页显示域名的 DNS 记录标签页" },
    { key: "enable_ip",           label: "IP 地理定位",      icon: RiMapPin2Line,      desc: "结果页显示 IP 归属地和 ASN 信息" },
    { key: "enable_ssl",          label: "SSL 证书检测",     icon: RiShieldCheckLine,  desc: "结果页显示域名 SSL 证书有效期和颁发机构" },
    { key: "enable_icp",          label: "ICP 备案查询",     icon: RiFileList3Line,    desc: "结果页显示域名 ICP 备案信息（中国大陆适用）" },
    { key: "enable_http",         label: "HTTP 状态检测",    icon: RiWifiLine,         desc: "结果页实时检测网站可访问性和 HTTP 响应状态" },
  ];

  const NAV_FEATURES: FeatureDef[] = [
    { key: "enable_remind",   label: "域名到期提醒", icon: RiAlarmLine,   desc: "用户可设置域名到期邮件提醒（需配置邮件服务）", adminLink: "/admin/reminders", adminLabel: "管理提醒", requires: "需配置邮件" },
    { key: "drop_calendar_public", label: "掉落日历公开", icon: RiCalendarLine, desc: "未登录用户可浏览公开掉落日历（关闭后需登录访问）", adminLink: "/drops", adminLabel: "查看日历" },
    { key: "enable_sponsor",  label: "赞助/打赏",    icon: RiHeartLine,   desc: "导航显示赞助入口，支持支付宝、微信、PayPal 等", adminLink: "/admin/sponsors", adminLabel: "管理赞助" },
    { key: "enable_tools",    label: "在线工具",     icon: RiToolsLine,   desc: "导航显示工具页面入口" },
    { key: "enable_links",    label: "友情链接",     icon: RiLinksLine,   desc: "导航显示友情链接页面", adminLink: "/admin/links", adminLabel: "管理链接" },
    { key: "enable_about",    label: "关于页面",     icon: RiInformationLine, desc: "导航显示站点介绍/关于页面" },
    { key: "enable_changelog",label: "更新日志",     icon: RiHistoryLine, desc: "导航显示版本更新日志页面", adminLink: "/admin/changelog", adminLabel: "管理日志" },
    { key: "enable_docs",     label: "API 文档",     icon: RiBook2Line,   desc: "导航显示 API 文档和接入说明" },
  ];

  function FeatureCard({ f }: { f: FeatureDef }) {
    const checked = s[f.key] === "1";
    return (
      <div className={cn(
        "flex gap-3 p-3 rounded-xl border transition-all",
        checked ? "border-primary/20 bg-primary/3" : "border-border hover:bg-muted/30",
      )}>
        {/* Icon */}
        <div className={cn(
          "w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 transition-colors",
          checked ? "bg-primary/10" : "bg-muted/50",
        )}>
          <f.icon className={cn("w-3.5 h-3.5", checked ? "text-primary" : "text-muted-foreground/50")} />
        </div>
        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-xs font-semibold leading-none">{f.label}</span>
            {f.requires && checked && (
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-200/60 dark:border-amber-800/40 font-medium">{f.requires}</span>
            )}
          </div>
          <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">{f.desc}</p>
          {f.adminLink && checked && (
            <Link
              href={f.adminLink}
              className="inline-flex items-center gap-1 mt-1.5 text-[10px] font-semibold text-primary/70 hover:text-primary transition-colors"
            >
              <RiArrowRightLine className="w-2.5 h-2.5" />
              {f.adminLabel}
            </Link>
          )}
        </div>
        {/* Toggle */}
        <button
          type="button"
          onClick={() => set(f.key, checked ? "" : "1")}
          className="shrink-0 self-start mt-0.5"
        >
          {checked
            ? <RiToggleFill className="w-8 h-8 text-primary" />
            : <RiToggleLine className="w-8 h-8 text-muted-foreground/40" />}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiSearchLine} title="查询结果页功能" desc="在 WHOIS 查询结果页中显示的附加功能标签页和操作" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {RESULT_FEATURES.map(f => <FeatureCard key={f.key as string} f={f} />)}
        </div>
      </div>
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiLinksLine} title="导航与独立页面" desc="在导航栏显示的功能入口页面" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {NAV_FEATURES.map(f => <FeatureCard key={f.key as string} f={f} />)}
        </div>
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
