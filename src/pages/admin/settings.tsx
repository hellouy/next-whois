import React from "react";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated, parseResultAds, serializeResultAds, type ResultAdItem, type ResultAdSlot } from "@/lib/site-settings";
import {
  EffectBadge, Field, MultiItemInput, PasswordField, SectionTitle, SelectField, TextareaField, Toggle, useUnsavedGuard,
} from "@/components/admin/settings-ui";
import Link from "next/link";
import {
  RiLoader4Line, RiCheckLine, RiToggleLine, RiToggleFill,
  RiGlobalLine, RiShieldCheckLine, RiSettings4Line,
  RiHomeLine, RiMailLine, RiBarChartLine, RiLockLine,
  RiMoneyDollarCircleLine, RiBankCardLine, RiImageLine,
  RiSaveLine, RiRefreshLine,
  RiCodeBoxLine, RiBellLine, RiUserLine, RiLinksLine,
  RiPaletteLine, RiSendPlane2Line, RiAlertLine, RiInformationLine,
  RiAddLine, RiDeleteBinLine, RiSearchLine,
  RiExternalLinkLine, RiMessage3Line, RiMedalLine, RiHeartLine,
  RiShareLine, RiServerLine, RiMapPin2Line, RiFileList3Line,
  RiToolsLine, RiAlarmLine, RiHistoryLine, RiBook2Line,
  RiArrowRightLine, RiTimerLine, RiWifiLine, RiCalendarLine,
  RiPaintLine, RiPaintFill, RiArrowDownSLine, RiArrowRightSLine,
  RiMegaphoneLine, RiAdvertisementLine, RiArrowUpSLine,
} from "@remixicon/react";

type TabKey =
  | "branding"
  | "ads"
  | "access"
  | "features"
  | "analytics";

const TABS: { key: TabKey; label: string; icon: React.ElementType }[] = [
  { key: "branding",  label: "外观与首页", icon: RiPaletteLine },
  { key: "ads",       label: "广告管理",   icon: RiMegaphoneLine },
  { key: "access",    label: "安全防护",   icon: RiShieldCheckLine },
  { key: "features",  label: "功能开关",   icon: RiSettings4Line },
  { key: "analytics", label: "统计分析",   icon: RiBarChartLine },
];

function AdEditor({
  ad, index, length, onUpdate, onRemove, onMoveUp, onMoveDown,
}: {
  ad: ResultAdItem;
  index: number;
  length: number;
  onUpdate: (patch: Partial<ResultAdItem>) => void;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}) {
  const [open, setOpen] = React.useState(index === 0);
  const enabled = ad.enabled === "1";

  return (
    <div className="rounded-xl border border-border/70 bg-muted/20 overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-1 px-3 py-2.5">
        <button
          type="button"
          onClick={() => setOpen(o => !o)}
          className="flex items-center gap-2 flex-1 min-w-0 text-left"
        >
          {open
            ? <RiArrowDownSLine className="w-4 h-4 text-muted-foreground shrink-0" />
            : <RiArrowRightSLine className="w-4 h-4 text-muted-foreground shrink-0" />}
          <span className="w-5 h-5 rounded-md border border-border/60 bg-background flex items-center justify-center text-[10px] font-bold text-muted-foreground shrink-0 tabular-nums">
            {index + 1}
          </span>
          <span className="text-xs font-semibold truncate">
            {ad.name?.trim() ? ad.name.trim() : `广告 ${index + 1}`}
          </span>
        </button>
        <button
          type="button"
          onClick={() => onUpdate({ enabled: enabled ? "" : "1" })}
          className={`flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-semibold border transition-colors shrink-0 ${enabled ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30" : "text-muted-foreground border-border"}`}
        >
          {enabled ? <RiCheckLine className="w-3 h-3" /> : <RiToggleLine className="w-3 h-3" />}
          {enabled ? "启用中" : "已停用"}
        </button>
        <div className="flex items-center gap-0.5 shrink-0">
          <button
            type="button"
            onClick={onMoveUp}
            disabled={index === 0}
            title="上移"
            className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground disabled:opacity-25 disabled:pointer-events-none"
          >
            <RiArrowUpSLine className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={onMoveDown}
            disabled={index === length - 1}
            title="下移"
            className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground disabled:opacity-25 disabled:pointer-events-none"
          >
            <RiArrowDownSLine className="w-3.5 h-3.5" />
          </button>
        </div>
        <button
          type="button"
          onClick={onRemove}
          title="删除此广告"
          className="p-1.5 rounded-lg hover:bg-destructive/10 transition-colors text-muted-foreground hover:text-destructive shrink-0"
        >
          <RiDeleteBinLine className="w-3.5 h-3.5" />
        </button>
      </div>

      {open && (
        <div className="px-3 pb-3 space-y-3 border-t border-border/60 pt-3">
          <Field label="广告名称" desc="仅后台管理用，帮助区分多条广告（可选）">
            <Input value={ad.name || ""} onChange={e => onUpdate({ name: e.target.value })} placeholder={`广告 ${index + 1}`} className="text-xs" />
          </Field>
          <Field label="推广文字" desc="支持多条，自动循环轮播；可设置颜色、大小、加粗">
            <MultiItemInput
              value={ad.text || ""}
              onChange={v => onUpdate({ text: v })}
              placeholder="推广/广告文字，多条用 | 分隔…"
            />
          </Field>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="图片 URL" desc="广告图片地址（横版横幅建议宽度 600–1200px；含义位可放更高的海报图）">
              <Input value={ad.image_url || ""} onChange={e => onUpdate({ image_url: e.target.value })} placeholder="https://example.com/banner.png" className="text-xs" />
            </Field>
            <Field label="图片 Alt 文字" desc="图片无法加载时显示的替代文字（同时用于 SEO）">
              <Input value={ad.image_alt || ""} onChange={e => onUpdate({ image_alt: e.target.value })} placeholder="广告" className="text-xs" />
            </Field>
          </div>
          {ad.image_url?.trim() && (
            <div className="rounded-xl border border-border/60 overflow-hidden bg-muted/30 p-2">
              <p className="text-[10px] text-muted-foreground mb-2">图片预览：</p>
              <img
                src={ad.image_url}
                alt={ad.image_alt || "广告预览"}
                className="max-w-full max-h-28 object-contain rounded-lg mx-auto block"
                onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
              />
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Field label="点击跳转链接" desc="点击广告时跳转的 URL（可选）">
              <Input value={ad.url || ""} onChange={e => onUpdate({ url: e.target.value })} placeholder="https://..." className="text-xs" />
            </Field>
            <Field label="推广标签文字" desc="显示在文字左侧的小标签，如「广告」「推广」「合作」">
              <Input value={ad.label || ""} onChange={e => onUpdate({ label: e.target.value })} placeholder="广告" className="text-xs" />
            </Field>
          </div>
          <div className="flex items-start gap-2 px-3 py-2 rounded-xl bg-amber-500/8 border border-amber-500/20">
            <RiAlertLine className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <p className="text-[11px] text-amber-700 dark:text-amber-400">
              自定义 HTML 会直接渲染且优先于图片/文字，请确保内容来源可信。支持嵌入第三方广告脚本（如 Google AdSense 等）。
            </p>
          </div>
          <TextareaField
            label="自定义 HTML 代码（可选）"
            desc="填入后本广告直接渲染 HTML，不再显示图片与文字"
            value={ad.html || ""}
            onChange={v => onUpdate({ html: v })}
            rows={4}
            placeholder={'<!-- 示例：Google AdSense -->\n<ins class="adsbygoogle"\n  style="display:block"\n  data-ad-client="ca-pub-XXXXXXXX"\n  data-ad-slot="XXXXXXXX"\n  data-ad-format="auto"></ins>'}
          />
        </div>
      )}
    </div>
  );
}

function AdSlotManager({
  s, set, slot, icon: Icon, title, desc,
}: {
  s: SiteSettings;
  set: (k: keyof SiteSettings, v: string) => void;
  slot: ResultAdSlot;
  icon: React.ElementType;
  title: string;
  desc: string;
}) {
  const map = parseResultAds(s.result_ads);
  const ads = map[slot];
  const persist = (next: ResultAdItem[]) => {
    const m = parseResultAds(s.result_ads);
    m[slot] = next;
    set("result_ads", serializeResultAds(m));
  };
  const update = (id: string, patch: Partial<ResultAdItem>) =>
    persist(ads.map(a => a.id === id ? { ...a, ...patch } : a));
  const remove = (id: string) => {
    if (typeof window !== "undefined" && window.confirm("确定删除这条广告？")) {
      persist(ads.filter(a => a.id !== id));
    }
  };
  const move = (idx: number, dir: -1 | 1) => {
    const j = idx + dir;
    if (j < 0 || j >= ads.length) return;
    const next = [...ads];
    [next[idx], next[j]] = [next[j], next[idx]];
    persist(next);
  };
  const add = () => {
    persist([...ads, {
      id: typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : String(Date.now()) + Math.random().toString(36).slice(2, 7),
      enabled: "1", name: "", text: "", image_url: "", image_alt: "", url: "", label: "广告", html: "",
    }]);
  };
  const enabledCount = ads.filter(a => a.enabled === "1").length;

  return (
    <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
      <SectionTitle icon={Icon} title={title} effect="结果页" desc={desc} />
      {ads.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-muted/50 border border-border text-[10px] font-semibold text-muted-foreground">
            <RiAdvertisementLine className="w-3 h-3" />
            共 {ads.length} 条
          </span>
          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full border text-[10px] font-semibold ${enabledCount > 0 ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30" : "text-muted-foreground border-border"}`}>
            <RiCheckLine className="w-3 h-3" />
            启用 {enabledCount} 条
          </span>
          {enabledCount === 0 && (
            <span className="text-[10px] text-amber-600 dark:text-amber-400">暂无可展示广告，页面不会显示此广告位</span>
          )}
        </div>
      )}
      {ads.length === 0 ? (
        <p className="text-[11px] text-muted-foreground/70 bg-muted/30 border border-dashed border-border rounded-xl px-3 py-4 text-center">
          此广告位暂无广告，点击下方按钮添加第一条
        </p>
      ) : (
        <div className="space-y-3">
          {ads.map((ad, i) => (
            <AdEditor
              key={ad.id}
              ad={ad}
              index={i}
              length={ads.length}
              onUpdate={patch => update(ad.id, patch)}
              onRemove={() => remove(ad.id)}
              onMoveUp={() => move(i, -1)}
              onMoveDown={() => move(i, 1)}
            />
          ))}
        </div>
      )}
      <button
        type="button"
        onClick={add}
        className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl border border-dashed border-border text-xs text-muted-foreground hover:text-foreground hover:border-primary/40 hover:bg-muted/40 transition-all"
      >
        <RiAddLine className="w-3.5 h-3.5" />
        添加广告
      </button>
    </div>
  );
}

function AdsTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  return (
    <div className="space-y-6">

      {/* ── 广告位说明 ─────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiAdvertisementLine}
          title="广告位说明"
          effect="结果页"
          desc="了解两个广告位的展示位置与时机，便于配置"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="rounded-xl border border-border/60 bg-muted/20 p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <RiImageLine className="w-3.5 h-3.5 text-primary" />
              <p className="text-xs font-semibold">广告位 1 · 含义位置</p>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              位于查询结果面板顶部。「域名含义」开启时此处显示含义说明，广告位 1 隐藏；关闭时广告位 1 的广告展示在原来的含义位置。
            </p>
          </div>
          <div className="rounded-xl border border-border/60 bg-muted/20 p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <RiLinksLine className="w-3.5 h-3.5 text-primary" />
              <p className="text-xs font-semibold">广告位 2 · 结果页底部</p>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              位于 WHOIS 查询结果页底部（桌面端居中横条；移动端在状态卡片上方内联）。始终展示。
            </p>
          </div>
        </div>
        <ul className="text-[11px] text-muted-foreground leading-relaxed list-disc list-inside space-y-0.5">
          <li>每条广告可同时配置文字、图片、跳转链接与自定义 HTML；填入 HTML 后优先渲染 HTML，其次是图片（可搭配文字），再是纯文字。</li>
          <li>同一广告位内的多条启用广告自上而下堆叠展示，可用每条的上下移按钮调整顺序。</li>
          <li>文字支持多条自动循环轮播（用 | 分隔，或 JSON 富文本设置颜色/字号/加粗）。</li>
        </ul>
      </div>

      {/* ── 域名含义 ─────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiBook2Line}
          title="域名含义"
          effect="结果页"
          desc="在 WHOIS 查询结果页顶部显示域名含义（基于 tian.hu 翻译数据）。关闭后，原含义位置将显示「广告位 1 · 含义位置」的广告内容"
        />
        <Toggle
          label="启用域名含义"
          checked={s.meaning_enabled === "1"}
          onChange={v => set("meaning_enabled", v ? "1" : "")}
        />
        {s.meaning_enabled !== "1" ? (
          <p className="text-[11px] text-amber-600 dark:text-amber-400 leading-relaxed">
            含义已关闭：查询结果页原「含义」位置会展示「广告位 1 · 含义位置」的广告（需该广告位存在启用状态的广告才会显示）。
          </p>
        ) : (
          <p className="text-[11px] text-sky-600 dark:text-sky-400 leading-relaxed">
            含义已开启：查询结果页顶部显示域名含义，「广告位 1 · 含义位置」暂不展示。若需在此处投放广告，请关闭域名含义。
          </p>
        )}
      </div>

      {/* ── 广告位 1 · 含义位置 ─────────────────────────────────── */}
      <AdSlotManager
        s={s}
        set={set}
        slot="slot1"
        icon={RiImageLine}
        title="广告位 1 · 含义位置"
        desc="显示在查询结果面板顶部。当「域名含义」关闭时，此广告位展示在原来的含义位置。可添加多条广告"
      />

      {/* ── 广告位 2 · 结果页底部 ────────────────────────────────── */}
      <AdSlotManager
        s={s}
        set={set}
        slot="slot2"
        icon={RiLinksLine}
        title="广告位 2 · 结果页底部"
        desc="显示在 WHOIS 查询结果页底部。每条广告支持文字、图片、跳转链接、自定义 HTML 组合，可添加多条"
      />
    </div>
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
            <Input value={s.site_logo_text} onChange={e => set("site_logo_text", e.target.value)} placeholder="域见你" className="text-xs" />
          </Field>
          <Field label="站点标题" desc="浏览器标签页 / SEO title">
            <Input value={s.site_title} onChange={e => set("site_title", e.target.value)} placeholder="域见你 · RDAP+WHOIS" className="text-xs" />
          </Field>
          <Field label="站点副标题" desc="首页 Logo 下方小字 & 导航栏 tagline">
            <Input value={s.site_subtitle} onChange={e => set("site_subtitle", e.target.value)} placeholder="专业的 WHOIS / RDAP 查询工具" className="text-xs" />
          </Field>
          <Field label="Favicon 图标 URL" desc="浏览器标签页图标（建议 32×32 PNG 或 SVG）">
            <Input value={s.site_icon_url} onChange={e => set("site_icon_url", e.target.value)} placeholder="https://..." className="text-xs" />
          </Field>
        </div>
        <Field label="页脚文字" desc="显示在所有页面底部（© 版权行）">
          <Input value={s.site_footer} onChange={e => set("site_footer", e.target.value)} placeholder="© 2026 域见你 · WHOIS & RDAP Lookup Service" className="text-xs" />
        </Field>
        <Field label="服务器信息来源" desc="注册商卡片「服务器信息」栏的归属文字（如：来自：不讲·李提供）">
          <Input value={s.whois_server_attribution} onChange={e => set("whois_server_attribution", e.target.value)} placeholder="来自：不讲·李提供" className="text-xs" />
        </Field>
      </div>

      {/* ── 站点背景 ────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiPaintLine}
          title="站点背景"
          effect="全站"
          desc="选择全站页面的背景样式，保存后立即生效"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {(
            [
              { value: "dot",       label: "点阵网格（默认）", desc: "原有细点阵 + 顶部渐隐，简洁低调" },
              { value: "dotfield",  label: "交互点阵（DotField）", desc: "Canvas 点阵，光标划过产生凹陷与光晕" },
              { value: "galaxy",    label: "星空星云（Galaxy）", desc: "WebGL 动态星云星场，支持鼠标交互" },
              { value: "stars",     label: "星空（Stars）", desc: "CSS 星光背景，鼠标移动产生视差" },
            ] as const
          ).map(opt => {
            const active = (s.site_background || "dot") === opt.value;
            return (
              <button
                key={opt.value}
                type="button"
                onClick={() => set("site_background", opt.value)}
                className={cn(
                  "text-left p-3 rounded-xl border transition-all",
                  active ? "border-primary/30 bg-primary/5" : "border-border hover:border-primary/30 hover:bg-muted/40",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-xs font-semibold">{opt.label}</p>
                  <span className={cn("w-3 h-3 rounded-full border transition-colors", active ? "bg-primary border-primary" : "border-border")} />
                </div>
                <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed">{opt.desc}</p>
              </button>
            );
          })}
        </div>
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
            <Input value={s.og_site_name} onChange={e => set("og_site_name", e.target.value)} placeholder="域见你" className="text-xs" />
          </Field>
          <Field label="站点 URL" desc="分享卡片的链接地址（影响 canonical URL）">
            <Input value={s.og_url} onChange={e => set("og_url", e.target.value)} placeholder="https://example.com" className="text-xs" />
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
        <SectionTitle icon={RiUserLine} title="注册与登录" effect="登录与验证" desc="控制用户注册方式和访问入口" />
        <Toggle label="开放注册" desc="允许新用户通过邮箱注册账号" checked={s.allow_registration === "1"} onChange={v => set("allow_registration", v ? "1" : "")} />
        <Toggle label="需要邀请码注册" desc="开启后注册时需要填写有效的邀请码" checked={s.require_invite_code === "1"} onChange={v => set("require_invite_code", v ? "1" : "")} />
        <Toggle label="登录后才能查询" desc="未登录用户无法进行任何查询" checked={s.require_login === "1"} onChange={v => set("require_login", v ? "1" : "")} />
        <Toggle label="禁用登录入口" desc="隐藏登录按钮，阻止用户登录（已登录用户不受影响）" checked={s.disable_login === "1"} onChange={v => set("disable_login", v ? "1" : "")} />
      </div>

      {/* ── 站点状态 ── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiLockLine} title="站点状态" effect="全站" desc="紧急管控与维护模式" />
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
        <SectionTitle icon={RiShieldCheckLine} title="人机验证 (CAPTCHA)" effect="登录与验证" desc='防止机器人和恶意请求；选择"不启用"关闭所有验证' />
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
          <SectionTitle icon={RiShieldCheckLine} title="Cloudflare Turnstile 密钥" effect="登录与验证" desc="在 Cloudflare Dashboard → Turnstile 获取" />
          <Field label="Site Key（公开密钥）">
            <Input value={s.captcha_turnstile_site_key} onChange={e => set("captcha_turnstile_site_key", e.target.value)} placeholder="0x..." className="text-xs" />
          </Field>
          <PasswordField label="Secret Key（私密密钥）" value={s.captcha_turnstile_secret_key} onChange={v => set("captcha_turnstile_secret_key", v)} />
        </div>
      )}
      {captchaProvider === "hcaptcha" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="hCaptcha 密钥" effect="登录与验证" desc="在 hcaptcha.com 后台获取" />
          <Field label="Site Key"><Input value={s.captcha_hcaptcha_site_key} onChange={e => set("captcha_hcaptcha_site_key", e.target.value)} placeholder="your-site-key" className="text-xs" /></Field>
          <PasswordField label="Secret Key" value={s.captcha_hcaptcha_secret_key} onChange={v => set("captcha_hcaptcha_secret_key", v)} />
        </div>
      )}
      {captchaProvider === "mtcaptcha" && (
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <SectionTitle icon={RiShieldCheckLine} title="MTCaptcha 密钥" effect="登录与验证" desc="在 mtcaptcha.com 后台获取" />
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
        <SectionTitle icon={RiSearchLine} title="查询结果页功能" effect="结果页" desc="在 WHOIS 查询结果页中显示的附加功能标签页和操作" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {RESULT_FEATURES.map(f => <FeatureCard key={f.key as string} f={f} />)}
        </div>
      </div>
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
        <SectionTitle icon={RiLinksLine} title="导航与独立页面" effect="全站" desc="在导航栏显示的功能入口页面" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {NAV_FEATURES.map(f => <FeatureCard key={f.key as string} f={f} />)}
        </div>
      </div>

      {/* ── 演示数据模式 ─────────────────────────────────────────── */}
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle
          icon={RiToolsLine}
          title="演示数据模式"
          effect="结果页"
          desc="开启后，查询命中指定后缀的域名将返回一组固定的演示数据，不再发起真实 WHOIS/RDAP 查询；其他域名不受影响"
        />
        <Toggle
          label="启用演示数据模式"
          desc="开启后，符合下方后缀的域名查询将被拦截并返回演示数据"
          checked={s.demo_mode_enabled === "1"}
          onChange={v => set("demo_mode_enabled", v ? "1" : "")}
        />
        <div className={cn("space-y-3 border-t border-border/40 pt-4 transition-opacity", s.demo_mode_enabled !== "1" && "opacity-50 pointer-events-none")}>
          <Field label="演示后缀" desc="命中即返回演示数据的后缀，多个用逗号分隔；不区分大小写与开头点号">
            <Input
              value={s.demo_tld}
              onChange={e => set("demo_tld", e.target.value)}
              placeholder="xx" className="text-xs font-mono"
            />
          </Field>
          <div className="rounded-xl bg-amber-500/8 border border-amber-500/20 px-3 py-2">
            <p className="text-[11px] text-amber-700 dark:text-amber-400 leading-relaxed">
              演示数据内容固定：注册人「不讲李」、国家「中国」、邮箱 domain@nic.rw、电话 15801580158、注册商 NIC.RW、
              状态正常（ok）、NS1.NIC.RW / NS2.NIC.RW。创建时间 = 查询时间前 1 小时，过期时间 = 创建时间 + 1 年，
              更新时间 = 查询时间。原始 WHOIS 文本同步模拟真实格式。
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function AnalyticsTab({ s, set }: { s: SiteSettings; set: (k: keyof SiteSettings, v: string) => void }) {
  return (
    <div className="space-y-6">
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
        <SectionTitle icon={RiBarChartLine} title="统计分析" effect="全站" desc="集成第三方统计服务" />
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
        <SectionTitle icon={RiCodeBoxLine} title="自定义 Head 脚本" effect="全站" desc="会被注入到每个页面 <head> 中的自定义代码（请谨慎填写）" />
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

export default function AdminSettingsPage() {
  const router = useRouter();
  const [settings, setSettings] = React.useState<SiteSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [dirty, setDirty] = React.useState(false);
  useUnsavedGuard(dirty);
  const [tab, setTab] = React.useState<TabKey>(() => {
    const t = router.query.tab;
    return (typeof t === "string" && (TABS.some(x => x.key === t))) ? (t as TabKey) : "branding";
  });

  React.useEffect(() => {
    const t = router.query.tab;
    if (typeof t === "string" && t !== tab && TABS.some(x => x.key === t)) {
      setTab(t as TabKey);
    }
  }, [router.query.tab]);

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
          {tab === "ads"       && <AdsTab {...tabProps} />}
          {tab === "access"    && <AccessTab {...tabProps} />}
          {tab === "features"  && <FeaturesTab {...tabProps} />}
          {tab === "analytics" && <AnalyticsTab {...tabProps} />}
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
