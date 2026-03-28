import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TextArea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { DEFAULT_SETTINGS, type SiteSettings, notifySettingsUpdated } from "@/lib/site-settings";
import {
  RiLoader4Line, RiSaveLine, RiRefreshLine, RiImageLine,
  RiGlobalLine, RiFileTextLine, RiShareLine, RiTwitterXLine,
  RiMegaphoneLine, RiMailSendLine, RiCheckLine, RiToggleLine,
  RiHomeLine, RiInformationLine, RiHistoryLine, RiLinksLine,
  RiHeartLine, RiBarChartLine, RiSearchLine, RiCodeBoxLine,
  RiShieldLine, RiPaletteLine, RiEyeLine, RiUploadLine, RiCloseLine,
  RiFingerprint2Line, RiUserLine, RiBankCardLine,
  RiAddLine, RiDeleteBinLine, RiAlertLine,
} from "@remixicon/react";

// ── Client-side image compression helper ────────────────────────────────────
// Resizes to maxPx on the longest side (preserving aspect ratio) and
// re-encodes as WebP at `quality` (0-1). Falls back to PNG for small images.
async function compressImage(
  file: File,
  maxPx = 2048,
  quality = 0.9,
): Promise<{ dataUrl: string; originalKB: number; compressedKB: number }> {
  const originalKB = Math.round(file.size / 1024);
  return new Promise((resolve, reject) => {
    const img = new Image();
    const blobUrl = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(blobUrl);
      let { width, height } = img;
      if (width > maxPx || height > maxPx) {
        if (width >= height) { height = Math.round((height / width) * maxPx); width = maxPx; }
        else                 { width = Math.round((width / height) * maxPx); height = maxPx; }
      }
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d")!;
      ctx.drawImage(img, 0, 0, width, height);
      // Try WebP first (best compression); fall back to PNG for transparency
      const webp = canvas.toDataURL("image/webp", quality);
      const dataUrl = webp.startsWith("data:image/webp") ? webp : canvas.toDataURL("image/png");
      const compressedKB = Math.round((dataUrl.length * 3) / 4 / 1024);
      resolve({ dataUrl, originalKB, compressedKB });
    };
    img.onerror = () => { URL.revokeObjectURL(blobUrl); reject(new Error("Invalid image")); };
    img.src = blobUrl;
  });
}

// ── ImageUploadField component ───────────────────────────────────────────────
function ImageUploadField({
  value,
  onChange,
  placeholder,
  hint,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  hint: string;
}) {
  const [uploading, setUploading] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    if (!file.type.startsWith("image/")) { toast.error("请选择图片文件"); return; }
    setUploading(true);
    try {
      const { dataUrl, originalKB, compressedKB } = await compressImage(file);
      const res = await fetch("/api/admin/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataUrl, hint }),
      });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error || "上传失败"); }
      const { url } = await res.json();
      onChange(url);
      const saved = originalKB > 0 ? Math.round((1 - compressedKB / originalKB) * 100) : 0;
      const msg = saved > 5
        ? `上传成功，已压缩 ${saved}%（${originalKB} KB → ${compressedKB} KB）`
        : `上传成功（${compressedKB} KB）`;
      toast.success(msg);
    } catch (e: any) {
      toast.error(e.message || "上传失败");
    } finally {
      setUploading(false);
    }
  }

  function onInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
    e.target.value = "";
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  }

  const isDataUrl = value.startsWith("data:image/");
  const previewSrc = value && (value.startsWith("/") || value.startsWith("http") || isDataUrl) ? value : null;

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <Input
          value={isDataUrl ? "" : value}
          onChange={e => onChange(e.target.value)}
          placeholder={isDataUrl ? "📎 已上传图片（点击×清除，或拖拽替换）" : placeholder}
          className="h-9 rounded-xl text-sm flex-1 min-w-0"
          readOnly={isDataUrl}
        />
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={onInputChange}
        />
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-9 rounded-xl px-3 gap-1.5 shrink-0 text-xs"
          disabled={uploading}
          onClick={() => inputRef.current?.click()}
          onDrop={onDrop}
          onDragOver={e => e.preventDefault()}
        >
          {uploading
            ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
            : <RiUploadLine className="w-3.5 h-3.5" />}
          {uploading ? "压缩中…" : "上传"}
        </Button>
      </div>
      {previewSrc && (
        <div className="relative inline-block group">
          <img
            src={previewSrc}
            alt="preview"
            className="h-16 max-w-[200px] rounded-lg border border-border object-contain bg-muted/30"
          />
          <button
            type="button"
            onClick={() => onChange("")}
            className="absolute -top-1.5 -right-1.5 w-5 h-5 rounded-full bg-destructive text-white flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
          >
            <RiCloseLine className="w-3 h-3" />
          </button>
        </div>
      )}
    </div>
  );
}

// ── ThanksListEditor ─────────────────────────────────────────────────────────
type ThanksItem = { name: string; url: string; desc: string; descEn: string };

function parseThanks(json: string): ThanksItem[] {
  try {
    const p = JSON.parse(json);
    if (Array.isArray(p)) return p.map(i => ({ name: i.name || "", url: i.url || "", desc: i.desc || "", descEn: i.descEn || "" }));
  } catch {}
  return [];
}

function ThanksListEditor({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [items, setItems] = React.useState<ThanksItem[]>(() => parseThanks(value));

  React.useEffect(() => {
    const fresh = parseThanks(value);
    setItems(fresh);
  }, []);

  function update(next: ThanksItem[]) {
    setItems(next);
    onChange(next.length ? JSON.stringify(next) : "");
  }

  function addItem() {
    update([...items, { name: "", url: "", desc: "", descEn: "" }]);
  }

  function removeItem(i: number) {
    update(items.filter((_, idx) => idx !== i));
  }

  function setField(i: number, field: keyof ThanksItem, val: string) {
    const next = items.map((item, idx) => idx === i ? { ...item, [field]: val } : item);
    update(next);
  }

  return (
    <div className="space-y-3">
      {items.length === 0 && (
        <p className="text-xs text-muted-foreground py-2 text-center bg-muted/30 rounded-xl border border-dashed border-border">
          暂无条目，点击「添加」按钮新增致谢项
        </p>
      )}
      {items.map((item, i) => (
        <div key={i} className="bg-muted/30 border border-border rounded-xl p-3 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground font-semibold bg-muted px-1.5 py-0.5 rounded shrink-0">#{i + 1}</span>
            <div className="flex-1 grid grid-cols-2 gap-2">
              <Input
                value={item.name}
                onChange={e => setField(i, "name", e.target.value)}
                placeholder="名称（如 Vercel）"
                className="h-8 rounded-lg text-xs"
              />
              <Input
                value={item.url}
                onChange={e => setField(i, "url", e.target.value)}
                placeholder="https://..."
                className="h-8 rounded-lg text-xs font-mono"
              />
            </div>
            <button
              type="button"
              onClick={() => removeItem(i)}
              className="w-7 h-7 flex items-center justify-center rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors shrink-0"
              title="删除"
            >
              <RiDeleteBinLine className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-2 pl-8">
            <Input
              value={item.desc}
              onChange={e => setField(i, "desc", e.target.value)}
              placeholder="中文描述"
              className="h-8 rounded-lg text-xs"
            />
            <Input
              value={item.descEn}
              onChange={e => setField(i, "descEn", e.target.value)}
              placeholder="English description"
              className="h-8 rounded-lg text-xs"
            />
          </div>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={addItem}
        className="h-8 rounded-xl gap-1.5 text-xs w-full border-dashed"
      >
        <RiAddLine className="w-3.5 h-3.5" />添加致谢条目
      </Button>
    </div>
  );
}

// ── ExtraLinksEditor ─────────────────────────────────────────────────────────
type ExtraLink = { label: string; url: string };

function parseExtraLinks(json: string): ExtraLink[] {
  try {
    const p = JSON.parse(json);
    if (Array.isArray(p)) return p.map(i => ({ label: i.label || "", url: i.url || "" }));
  } catch {}
  return [];
}

function ExtraLinksEditor({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [items, setItems] = React.useState<ExtraLink[]>(() => parseExtraLinks(value));

  React.useEffect(() => {
    setItems(parseExtraLinks(value));
  }, []);

  function update(next: ExtraLink[]) {
    setItems(next);
    onChange(next.length ? JSON.stringify(next) : "");
  }

  function addItem() {
    update([...items, { label: "", url: "" }]);
  }

  function removeItem(i: number) {
    update(items.filter((_, idx) => idx !== i));
  }

  function setField(i: number, field: keyof ExtraLink, val: string) {
    const next = items.map((item, idx) => idx === i ? { ...item, [field]: val } : item);
    update(next);
  }

  return (
    <div className="space-y-2">
      {items.length === 0 && (
        <p className="text-xs text-muted-foreground py-2 text-center bg-muted/30 rounded-xl border border-dashed border-border">
          暂无条目，点击「添加」按钮新增赞助链接
        </p>
      )}
      {items.map((item, i) => (
        <div key={i} className="flex items-center gap-2 bg-muted/30 border border-border rounded-xl p-2">
          <span className="text-[10px] text-muted-foreground font-semibold bg-muted px-1.5 py-0.5 rounded shrink-0">#{i + 1}</span>
          <Input
            value={item.label}
            onChange={e => setField(i, "label", e.target.value)}
            placeholder="按钮文字（如 Ko-fi）"
            className="h-8 rounded-lg text-xs flex-1"
          />
          <Input
            value={item.url}
            onChange={e => setField(i, "url", e.target.value)}
            placeholder="https://..."
            className="h-8 rounded-lg text-xs flex-1 font-mono"
          />
          <button
            type="button"
            onClick={() => removeItem(i)}
            className="w-7 h-7 flex items-center justify-center rounded-lg text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors shrink-0"
            title="删除"
          >
            <RiDeleteBinLine className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={addItem}
        className="h-8 rounded-xl gap-1.5 text-xs w-full border-dashed"
      >
        <RiAddLine className="w-3.5 h-3.5" />添加赞助链接
      </Button>
    </div>
  );
}

type FieldDef = {
  key: keyof SiteSettings;
  label: string;
  desc: string;
  placeholder: string;
  icon: React.ElementType;
  multiline?: boolean;
  isImage?: boolean;
  customEditor?: "thanks-list" | "extra-links";
};

type ToggleDef = {
  key: keyof SiteSettings;
  label: string;
  desc: string;
  onColor: string;
};

type Section = {
  id: string;
  title: string;
  icon: React.ElementType;
  color: string;
  fields?: FieldDef[];
  toggles?: ToggleDef[];
};

const SECTIONS: Section[] = [
  {
    id: "branding",
    title: "品牌与基础信息",
    icon: RiPaletteLine,
    color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
    fields: [
      { key: "site_title", label: "网站标题", desc: "浏览器标签页和搜索结果中显示的标题", placeholder: "X.RW · RDAP+WHOIS", icon: RiGlobalLine },
      { key: "site_logo_text", label: "Logo 文字", desc: "导航栏中显示的品牌名称（留空使用网站标题）", placeholder: "X.RW", icon: RiGlobalLine },
      { key: "site_subtitle", label: "网站副标题", desc: "首页 Hero 区域下方的副标题文字", placeholder: "专业的 WHOIS / RDAP 查询工具", icon: RiFileTextLine },
      { key: "site_description", label: "网站描述 (SEO)", desc: "搜索引擎结果中显示的描述文字", placeholder: "快速查询域名、IP、ASN、CIDR...", icon: RiFileTextLine },
      { key: "site_keywords", label: "搜索关键词 (SEO)", desc: "meta keywords 标签内容，多个关键词用英文逗号分隔", placeholder: "Whois, RDAP, Lookup, Domain, IPv4, ASN", icon: RiSearchLine },
      { key: "site_footer", label: "页脚文字", desc: "页面底部显示的版权/说明文字", placeholder: "© 2025 X.RW · WHOIS & RDAP Lookup Service", icon: RiFileTextLine },
      { key: "site_icon_url", label: "网站图标", desc: "Favicon 图标（支持直接上传，留空使用默认图标）", placeholder: "https://example.com/favicon.ico", icon: RiImageLine, isImage: true },
    ],
  },
  {
    id: "home",
    title: "首页内容",
    icon: RiHomeLine,
    color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
    fields: [
      { key: "home_hero_title", label: "首页大标题", desc: "覆盖默认大标题文字（留空使用默认）", placeholder: "WHOIS / RDAP 查询", icon: RiHomeLine },
      { key: "home_hero_subtitle", label: "首页副标题", desc: "覆盖首页 Hero 区域的副标题（留空使用 site_subtitle）", placeholder: "快速查询域名、IP、ASN...", icon: RiFileTextLine },
      { key: "home_placeholder", label: "搜索框占位文字", desc: "搜索输入框内的提示文字（留空使用默认）", placeholder: "输入域名、IP、ASN...", icon: RiSearchLine },
    ],
    toggles: [
      { key: "home_show_stats", label: "显示查询统计数字", desc: "首页显示总查询次数等统计数据", onColor: "bg-emerald-500" },
    ],
  },
  {
    id: "announcement",
    title: "公告与维护",
    icon: RiMegaphoneLine,
    color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
    fields: [
      { key: "site_announcement", label: "公告横幅内容", desc: "显示在页面顶部的公告文字（留空则不显示公告条）", placeholder: "🎉 欢迎使用 X.RW！", icon: RiMegaphoneLine },
      { key: "maintenance_message", label: "维护模式自定义消息", desc: "维护页面显示给访客的额外说明（开启维护模式时生效，留空则显示 site_announcement 内容）", placeholder: "预计维护时间：今晚 22:00 - 23:00，感谢您的耐心等待 🙏", icon: RiAlertLine, multiline: false },
    ],
  },
  {
    id: "og",
    title: "社交分享 / Open Graph",
    icon: RiShareLine,
    color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
    fields: [
      { key: "og_site_name", label: "og:site_name", desc: "链接预览中显示的站点名称", placeholder: "X.RW · RDAP+WHOIS", icon: RiShareLine },
      { key: "og_url", label: "规范链接 (og:url)", desc: "网站主域名，用于 og:url 和 canonical 标签", placeholder: "https://whois.example.com", icon: RiGlobalLine },
      { key: "og_image", label: "通用分享图（微信 / Facebook / 默认）", desc: "社交分享默认图片，微信、Facebook、YouTube 均使用此图（建议 1200×630，支持直接上传）", placeholder: "https://example.com/og-image.png", icon: RiImageLine, isImage: true },
      { key: "og_image_wechat", label: "微信专用图", desc: "微信分享时优先使用此图（建议 1:1 方形或 1200×630，支持直接上传）", placeholder: "https://example.com/wechat-share.png", icon: RiImageLine, isImage: true },
      { key: "og_image_facebook", label: "Facebook 专用图", desc: "Facebook 分享时优先使用此图（建议 1200×630，支持直接上传）", placeholder: "https://example.com/fb-share.png", icon: RiImageLine, isImage: true },
      { key: "og_image_twitter", label: "X（Twitter）专用图", desc: "X / Twitter 分享时使用此图（twitter:image meta 标签，支持直接上传）", placeholder: "https://example.com/twitter-card.png", icon: RiTwitterXLine, isImage: true },
      { key: "og_image_youtube", label: "YouTube 专用图", desc: "YouTube 链接预览时优先使用此图（建议 1280×720，支持直接上传）", placeholder: "https://example.com/youtube-card.png", icon: RiImageLine, isImage: true },
      { key: "twitter_card", label: "Twitter Card 类型", desc: "summary 或 summary_large_image（推荐大图）", placeholder: "summary_large_image", icon: RiTwitterXLine },
    ],
  },
  {
    id: "about",
    title: "关于页面",
    icon: RiInformationLine,
    color: "bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400",
    fields: [
      { key: "about_title", label: "页面标题", desc: "关于页面的标题文字（留空使用默认）", placeholder: "关于我们", icon: RiInformationLine },
      { key: "about_content", label: "中文简介", desc: "关于页面的中文介绍段落（留空使用内置默认文案）", placeholder: "这里填写关于本站的中文介绍...", icon: RiFileTextLine, multiline: true },
      { key: "about_intro_en", label: "英文简介", desc: "关于页面的英文介绍段落（留空使用内置默认文案）", placeholder: "Enter the English description for the about page...", icon: RiFileTextLine, multiline: true },
      { key: "about_contact_email", label: "联系邮箱", desc: "显示在关于页面和友情链接页的联系邮箱（留空则不显示）", placeholder: "contact@yourdomain.com", icon: RiMailSendLine },
      { key: "about_github_url", label: "源码 GitHub 链接", desc: "GitHub 仓库地址（留空使用默认 zmh-program/next-whois）", placeholder: "https://github.com/yourname/yourrepo", icon: RiCodeBoxLine },
      { key: "about_author_name", label: "原作者名称", desc: "显示在【基于…二次创作】卡片中的原作者名称（留空使用默认 zmh-program）", placeholder: "zmh-program", icon: RiUserLine },
      { key: "about_author_url", label: "原作者主页链接", desc: "原作者个人主页（留空使用默认 https://zmh.me）", placeholder: "https://zmh.me", icon: RiLinksLine },
      { key: "about_thanks", label: "致谢列表", desc: "致谢服务商/支持者列表，点击「添加」逐条填写，留空使用内置默认列表", placeholder: "", icon: RiCodeBoxLine, customEditor: "thanks-list" },
    ],
  },
  {
    id: "changelog",
    title: "更新日志页面",
    icon: RiHistoryLine,
    color: "bg-indigo-100 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400",
    fields: [
      { key: "changelog_title", label: "更新日志标题", desc: "覆盖默认标题（留空使用默认）", placeholder: "更新日志", icon: RiHistoryLine },
    ],
  },
  {
    id: "links",
    title: "外部链接页面",
    icon: RiLinksLine,
    color: "bg-teal-100 dark:bg-teal-950/40 text-teal-600 dark:text-teal-400",
    fields: [
      { key: "links_title", label: "友链页面标题", desc: '覆盖默认标题（留空使用"友情链接"）', placeholder: "友情链接", icon: RiLinksLine },
      { key: "links_content", label: "友链页面副标题", desc: "页面头部的一句话描述（留空使用默认）", placeholder: "站长精选推荐 · 朋友们的网站", icon: RiFileTextLine },
    ],
  },
  {
    id: "sponsor",
    title: "赞助页面",
    icon: RiHeartLine,
    color: "bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400",
    fields: [
      { key: "sponsor_page_title", label: "赞助页面标题", desc: "赞助页面的主标题文字", placeholder: "赞助支持", icon: RiHeartLine },
      { key: "sponsor_page_desc", label: "赞助页面描述", desc: "赞助页面的描述/说明文字", placeholder: "感谢您对本项目的支持！", icon: RiFileTextLine, multiline: true },
      { key: "sponsor_alipay_qr", label: "支付宝收款码", desc: "支付宝收款二维码（支持直接上传）", placeholder: "https://example.com/alipay-qr.png", icon: RiImageLine, isImage: true },
      { key: "sponsor_wechat_qr", label: "微信收款码", desc: "微信收款二维码（支持直接上传）", placeholder: "https://example.com/wechat-qr.png", icon: RiImageLine, isImage: true },
      { key: "sponsor_github_url", label: "GitHub Sponsors 链接", desc: "GitHub Sponsors 主页链接（显示 GitHub 赞助按钮）", placeholder: "https://github.com/sponsors/yourname", icon: RiLinksLine },
      { key: "sponsor_paypal_url", label: "PayPal 收款链接", desc: "PayPal.me 或 PayPal 付款链接（显示 PayPal 赞助按钮）", placeholder: "https://paypal.me/yourname", icon: RiLinksLine },
      { key: "sponsor_crypto_btc", label: "BTC 钱包地址", desc: "Bitcoin 收款地址（留空隐藏）", placeholder: "bc1q...", icon: RiLinksLine },
      { key: "sponsor_crypto_eth", label: "ETH 钱包地址", desc: "Ethereum 收款地址（留空隐藏）", placeholder: "0x...", icon: RiLinksLine },
      { key: "sponsor_crypto_usdt", label: "USDT 钱包地址", desc: "Tether 收款地址（留空隐藏）", placeholder: "T...", icon: RiLinksLine },
      { key: "sponsor_crypto_usdt_network", label: "USDT 转账网络", desc: "填写网络名称，将在收款页面醒目提示用户（如留空则根据地址自动识别）。例如：TRC20 (Tron)、ERC20 (Ethereum)、BEP20 (BSC)、Polygon (MATIC)", placeholder: "TRC20 (Tron)", icon: RiLinksLine },
      { key: "sponsor_crypto_okx", label: "OKX / Web3 钱包地址", desc: "OKX 或其他 Web3 钱包地址（留空隐藏）", placeholder: "0x...", icon: RiLinksLine },
      { key: "sponsor_extra_links", label: "其他赞助链接", desc: "额外显示的赞助按钮，点击「添加」逐条填写按钮文字和链接", placeholder: "", icon: RiLinksLine, customEditor: "extra-links" },
    ],
  },
  {
    id: "analytics",
    title: "统计分析",
    icon: RiBarChartLine,
    color: "bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400",
    fields: [
      { key: "analytics_google", label: "Google Analytics ID", desc: "Google Analytics 4 的测量 ID，如 G-XXXXXXXXXX（留空禁用）", placeholder: "G-XXXXXXXXXX", icon: RiBarChartLine },
      { key: "analytics_umami", label: "Umami Website ID", desc: "Umami 统计的 Website ID（留空禁用）", placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", icon: RiBarChartLine },
      { key: "analytics_umami_src", label: "Umami 脚本地址", desc: "自托管 Umami 的脚本 URL（留空使用默认云服务）", placeholder: "https://umami.example.com/script.js", icon: RiCodeBoxLine },
      { key: "custom_head_script", label: "自定义 <head> 代码", desc: "注入到所有页面 <head> 中的自定义 HTML/JS 代码（谨慎使用）", placeholder: "<!-- 自定义脚本/像素代码 -->", icon: RiCodeBoxLine, multiline: true },
    ],
  },
];

const FEATURE_GROUPS: { title: string; icon: React.ElementType; color: string; items: ToggleDef[] }[] = [
  {
    title: "访问控制",
    icon: RiShieldLine,
    color: "bg-slate-100 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400",
    items: [
      { key: "allow_registration", label: "开放注册", desc: "允许新用户自助注册账户（关闭后注册页显示提示，已有账号不受影响）", onColor: "bg-emerald-500" },
      { key: "require_login", label: "登录后才可查询", desc: "未登录访客无法进行任何查询，仅可浏览首页", onColor: "bg-amber-500" },
      { key: "disable_login", label: "禁用登录入口", desc: "隐藏导航栏登录按钮并关闭登录页；管理员仍可通过直接访问 /login 登录", onColor: "bg-red-500" },
      { key: "maintenance_mode", label: "维护模式", desc: "对所有非管理员用户显示「维护中」提示页，站点暂停对外服务", onColor: "bg-orange-500" },
      { key: "query_only_mode", label: "纯查询模式", desc: "隐藏用户账户、控制台、历史记录等功能，仅保留域名查询核心功能", onColor: "bg-violet-500" },
      { key: "hide_raw_whois", label: "隐藏原始 WHOIS", desc: "查询结果不显示原始 WHOIS / RDAP 报文，仅展示解析后的结构化信息", onColor: "bg-slate-500" },
    ],
  },
  {
    title: "核心查询功能",
    icon: RiSearchLine,
    color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
    items: [
      { key: "enable_search_links", label: "搜索引擎外链", desc: "查询结果页显示「在搜索引擎中查询」卡片，含 Google/Bing/百度 跳转链接及收录查询", onColor: "bg-emerald-500" },
      { key: "enable_feedback", label: "结果反馈入口", desc: "查询结果页底部显示「反馈问题」按钮", onColor: "bg-emerald-500" },
      { key: "enable_share", label: "分享按钮", desc: "查询结果页显示分享/导出功能入口", onColor: "bg-emerald-500" },
      { key: "enable_stamps", label: "品牌认领 (Stamps)", desc: "允许用户为域名申请添加品牌标签", onColor: "bg-emerald-500" },
      { key: "enable_remind", label: "到期提醒", desc: "在导航和查询结果中显示域名到期订阅提醒功能", onColor: "bg-emerald-500" },
    ],
  },
  {
    title: "导航页面开关",
    icon: RiEyeLine,
    color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
    items: [
      { key: "enable_dns", label: "DNS 查询页", desc: "显示 DNS 解析查询工具入口", onColor: "bg-emerald-500" },
      { key: "enable_ip", label: "IP 查询页", desc: "显示 IP 信息查询工具入口", onColor: "bg-emerald-500" },
      { key: "enable_ssl", label: "SSL 检测页", desc: "显示 SSL 证书检测工具入口", onColor: "bg-emerald-500" },
      { key: "enable_icp", label: "ICP 备案查询页", desc: "显示 ICP 备案信息查询工具入口", onColor: "bg-emerald-500" },
      { key: "enable_http", label: "HTTP 检测页", desc: "显示 HTTP 请求状态检测工具入口", onColor: "bg-emerald-500" },
      { key: "enable_tools", label: "工具中心页", desc: "显示综合工具集合页入口", onColor: "bg-emerald-500" },
      { key: "enable_about", label: "关于页面", desc: "在导航中显示关于页面链接", onColor: "bg-emerald-500" },
      { key: "enable_changelog", label: "更新日志页", desc: "在导航中显示更新日志链接", onColor: "bg-emerald-500" },
      { key: "enable_docs", label: "API 文档页", desc: "在导航中显示 API 文档链接", onColor: "bg-emerald-500" },
      { key: "enable_links", label: "外部链接页", desc: "在导航中显示友情链接/外部链接页面", onColor: "bg-emerald-500" },
      { key: "enable_sponsor", label: "赞助页面", desc: "在导航中显示赞助支持页面入口", onColor: "bg-rose-500" },
    ],
  },
  {
    title: "首页展示",
    icon: RiHomeLine,
    color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
    items: [
      { key: "home_show_stats", label: "显示统计数字", desc: "首页显示总查询次数等实时统计数据", onColor: "bg-emerald-500" },
    ],
  },
];

function Toggle({ value, onChange, onColor }: { value: boolean; onChange: (v: boolean) => void; onColor: string }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={[
        "relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none",
        value ? onColor : "bg-muted",
      ].join(" ")}
    >
      <span
        className={[
          "pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out",
          value ? "translate-x-4" : "translate-x-0",
        ].join(" ")}
      />
    </button>
  );
}

export default function AdminSettingsPage() {
  const [form, setForm] = React.useState<SiteSettings>(DEFAULT_SETTINGS);
  const [saved, setSaved] = React.useState<SiteSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [testingEmail, setTestingEmail] = React.useState(false);
  const [emailOk, setEmailOk] = React.useState<boolean | null>(null);
  const [activeSection, setActiveSection] = React.useState("branding");

  const isDirty = !loading && JSON.stringify(form) !== JSON.stringify(saved);

  const set = (key: keyof SiteSettings, value: string) =>
    setForm(prev => ({ ...prev, [key]: value }));
  const toggle = (key: keyof SiteSettings, value: boolean) =>
    setForm(prev => ({ ...prev, [key]: value ? "1" : "" }));
  const isOn = (key: keyof SiteSettings) => form[key] === "1";

  async function handleTestEmail() {
    setTestingEmail(true);
    setEmailOk(null);
    try {
      const res = await fetch("/api/admin/test-email", { method: "POST" });
      const data = await res.json();
      if (res.ok && data.ok) {
        setEmailOk(true);
        toast.success(`测试邮件已发送至 ${data.to}${data.provider ? `（通道：${data.provider}）` : ""}`);
      } else {
        setEmailOk(false);
        toast.error(data.error || "发送失败");
      }
    } catch {
      setEmailOk(false);
      toast.error("网络错误，发送失败");
    } finally {
      setTestingEmail(false);
    }
  }

  React.useEffect(() => {
    fetch("/api/admin/settings")
      .then(r => r.json())
      .then(data => {
        if (data.settings) {
          const merged = { ...DEFAULT_SETTINGS, ...data.settings };
          setForm(merged);
          setSaved(merged);
        }
      })
      .catch(() => toast.error("加载设置失败"))
      .finally(() => setLoading(false));
  }, []);

  async function handleSave() {
    setSaving(true);
    try {
      const res = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      setSaved({ ...form });
      notifySettingsUpdated();
      toast.success("设置已保存，已同步到所有页面");
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setSaving(false);
    }
  }

  function reset() {
    setForm(DEFAULT_SETTINGS);
    toast.info("已重置为默认值（尚未保存）");
  }

  const allSections = [
    ...SECTIONS.map(s => ({ id: s.id, title: s.title, icon: s.icon })),
    { id: "features", title: "功能开关", icon: RiToggleLine },
    { id: "email", title: "邮件系统", icon: RiMailSendLine },
    { id: "captcha", title: "人机验证", icon: RiFingerprint2Line },
    { id: "payment", title: "支付网关", icon: RiBankCardLine },
  ];

  return (
    <AdminLayout title="网站设置">
      <div className="space-y-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">网站设置</h2>
            <p className="text-xs text-muted-foreground mt-0.5">全面配置网站内容、功能开关、分析统计等</p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={reset} disabled={saving || loading} className="rounded-xl h-9 gap-2 text-sm">
                <RiRefreshLine className="w-4 h-4" />重置默认
              </Button>
              <Button onClick={handleSave} disabled={saving || loading} className="rounded-xl h-9 gap-2 text-sm font-semibold">
                {saving ? <><RiLoader4Line className="w-4 h-4 animate-spin" />保存中…</> : <><RiSaveLine className="w-4 h-4" />保存所有设置</>}
              </Button>
            </div>
            <p className="text-[10px] text-muted-foreground/70 text-right">
              点击保存后立即写入数据库 · 当前浏览器即时生效 · 其他会话 60 秒内同步
            </p>
          </div>
        </div>

        {isDirty && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200/60 dark:border-amber-700/30">
            <RiAlertLine className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
            <span className="text-sm text-amber-700 dark:text-amber-400 flex-1">有未保存的更改，切换页面后请记得保存</span>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={saving}
              className="h-7 px-3 text-xs rounded-lg gap-1.5 shrink-0 bg-amber-600 hover:bg-amber-700 text-white border-0"
            >
              {saving ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiSaveLine className="w-3 h-3" />}
              立即保存
            </Button>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-20">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : (
          <div className="flex gap-5">
            {/* Sidebar navigation */}
            <div className="hidden lg:flex flex-col gap-1 w-44 shrink-0">
              {allSections.map(({ id, title, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setActiveSection(id)}
                  className={[
                    "flex items-center gap-2 px-3 py-2 rounded-xl text-sm text-left transition-all",
                    activeSection === id
                      ? "bg-primary text-primary-foreground font-semibold"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/60",
                  ].join(" ")}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span className="truncate">{title}</span>
                </button>
              ))}
            </div>

            {/* Main content */}
            <div className="flex-1 min-w-0 space-y-5">
              {/* Mobile section selector */}
              <div className="lg:hidden">
                <select
                  value={activeSection}
                  onChange={e => setActiveSection(e.target.value)}
                  className="w-full h-9 rounded-xl border border-border bg-background px-3 text-sm"
                >
                  {allSections.map(({ id, title }) => (
                    <option key={id} value={id}>{title}</option>
                  ))}
                </select>
              </div>

              {/* Text/content sections */}
              {SECTIONS.filter(s => s.id === activeSection).map(section => {
                const SectionIcon = section.icon;
                return (
                  <div key={section.id} className="space-y-4">
                    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                      <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                        <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${section.color}`}>
                          <SectionIcon className="w-3.5 h-3.5" />
                        </div>
                        <h3 className="text-sm font-bold">{section.title}</h3>
                      </div>
                      <div className="p-5 space-y-5">
                        {section.fields?.map(({ key, label, desc, placeholder, icon: Icon, multiline, isImage, customEditor }) => (
                          <div key={key} className="space-y-1.5">
                            <div className="flex items-start gap-1.5">
                              <Icon className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
                              <div>
                                <Label className="text-sm font-semibold leading-none">{label}</Label>
                                <p className="text-[11px] text-muted-foreground mt-0.5">{desc}</p>
                              </div>
                            </div>
                            {isImage ? (
                              <ImageUploadField
                                value={form[key]}
                                onChange={v => set(key, v)}
                                placeholder={placeholder}
                                hint={key}
                              />
                            ) : customEditor === "thanks-list" ? (
                              <ThanksListEditor value={form[key]} onChange={v => set(key, v)} />
                            ) : customEditor === "extra-links" ? (
                              <ExtraLinksEditor value={form[key]} onChange={v => set(key, v)} />
                            ) : multiline ? (
                              <TextArea
                                value={form[key]}
                                onChange={e => set(key, e.target.value)}
                                placeholder={placeholder}
                                className="rounded-xl text-sm min-h-[90px] resize-y"
                              />
                            ) : (
                              <Input
                                value={form[key]}
                                onChange={e => set(key, e.target.value)}
                                placeholder={placeholder}
                                className="h-9 rounded-xl text-sm"
                              />
                            )}
                          </div>
                        ))}
                        {section.toggles?.map(({ key, label, desc, onColor }) => (
                          <div key={key} className="flex items-center justify-between gap-4 py-1">
                            <div>
                              <p className="text-sm font-semibold">{label}</p>
                              <p className="text-[11px] text-muted-foreground mt-0.5">{desc}</p>
                            </div>
                            <Toggle value={isOn(key)} onChange={v => toggle(key, v)} onColor={onColor} />
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}

              {/* Features section */}
              {activeSection === "features" && (
                <div className="space-y-4">
                  {/* Admin email config */}
                  <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                    <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400">
                        <RiShieldLine className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-sm font-bold">管理员配置</h3>
                    </div>
                    <div className="p-5 space-y-3">
                      <div className="space-y-1.5">
                        <Label htmlFor="admin_email" className="text-xs font-semibold flex items-center gap-1.5">
                          <RiUserLine className="w-3.5 h-3.5" />管理员邮箱
                        </Label>
                        <Input
                          id="admin_email"
                          type="email"
                          value={form.admin_email}
                          onChange={e => set("admin_email", e.target.value)}
                          placeholder="admin@example.com（留空使用初始默认管理员）"
                          className="h-9 rounded-xl text-sm font-mono"
                        />
                        <p className="text-[11px] text-muted-foreground">
                          拥有管理员权限的账户邮箱地址。修改后需使用新邮箱账户登录才能访问后台。留空则使用系统内置默认管理员账号。
                        </p>
                      </div>
                    </div>
                  </div>

                  {FEATURE_GROUPS.map(group => {
                    const GroupIcon = group.icon;
                    return (
                      <div key={group.title} className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                          <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${group.color}`}>
                            <GroupIcon className="w-3.5 h-3.5" />
                          </div>
                          <h3 className="text-sm font-bold">{group.title}</h3>
                        </div>
                        <div className="divide-y divide-border/50">
                          {group.items.map(({ key, label, desc, onColor }) => (
                            <div key={key} className="flex items-center justify-between gap-4 px-5 py-3">
                              <div>
                                <p className="text-sm font-semibold">{label}</p>
                                <p className="text-[11px] text-muted-foreground mt-0.5">{desc}</p>
                              </div>
                              <Toggle value={isOn(key)} onChange={v => toggle(key, v)} onColor={onColor} />
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}

                  {/* AI service quick link card */}
                  <a
                    href="/admin/api"
                    className="block glass-panel border border-dashed border-border rounded-2xl overflow-hidden hover:border-primary/40 hover:bg-primary/5 transition-all group"
                  >
                    <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border/60 bg-muted/20">
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-purple-100 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400">
                        <RiFingerprint2Line className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-sm font-bold">AI 服务 & API 接入</h3>
                      <span className="ml-auto text-[10px] text-muted-foreground group-hover:text-primary transition-colors">前往配置 →</span>
                    </div>
                    <div className="px-5 py-3">
                      <p className="text-[11px] text-muted-foreground leading-relaxed">
                        AI 大模型密钥（智谱、Groq、Gemini、DeepSeek、百炼、月之暗面、SiliconFlow）、第三方数据源接入、Resend 邮件服务等配置均在「API 接入」页面管理。
                      </p>
                    </div>
                  </a>
                </div>
              )}

              {/* Email section */}
              {activeSection === "email" && (
                <div className="space-y-4">
                  {/* SMTP Config */}
                  <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                    <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400">
                        <RiMailSendLine className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-sm font-bold">SMTP 自定义邮件服务</h3>
                      <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold">推荐</span>
                    </div>
                    <div className="p-5 space-y-4">
                      {/* Enable toggle */}
                      <div className="flex items-center justify-between gap-4">
                        <div>
                          <p className="text-sm font-semibold">启用 SMTP 发送</p>
                          <p className="text-xs text-muted-foreground mt-0.5">开启后所有系统邮件将通过 SMTP 发送，优先级高于 Resend</p>
                        </div>
                        <button
                          type="button"
                          role="switch"
                          aria-checked={!!form.smtp_enabled}
                          onClick={() => set("smtp_enabled", form.smtp_enabled ? "" : "1")}
                          className={[
                            "relative w-10 h-6 rounded-full transition-colors shrink-0",
                            form.smtp_enabled ? "bg-emerald-500" : "bg-muted-foreground/25",
                          ].join(" ")}
                        >
                          <span className={[
                            "absolute top-1 w-4 h-4 rounded-full bg-white shadow transition-transform",
                            form.smtp_enabled ? "translate-x-5" : "translate-x-1",
                          ].join(" ")} />
                        </button>
                      </div>

                      {/* SMTP fields */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div className="space-y-1.5">
                          <Label className="text-xs font-semibold">SMTP 服务器地址</Label>
                          <Input
                            value={form.smtp_host}
                            onChange={e => set("smtp_host", e.target.value)}
                            placeholder="smtp.qq.com / smtp.163.com / smtp.gmail.com"
                            className="h-9 rounded-xl text-sm font-mono"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <Label className="text-xs font-semibold">端口</Label>
                          <Input
                            value={form.smtp_port}
                            onChange={e => set("smtp_port", e.target.value)}
                            placeholder="465（SSL）/ 587（STARTTLS）/ 25"
                            className="h-9 rounded-xl text-sm font-mono"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <Label className="text-xs font-semibold">加密方式</Label>
                          <select
                            value={form.smtp_secure}
                            onChange={e => set("smtp_secure", e.target.value)}
                            className="w-full h-9 px-3 rounded-xl border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition"
                          >
                            <option value="ssl">SSL/TLS（端口 465，推荐）</option>
                            <option value="starttls">STARTTLS（端口 587）</option>
                            <option value="none">无加密（端口 25，不推荐）</option>
                          </select>
                        </div>
                        <div className="space-y-1.5">
                          <Label className="text-xs font-semibold">发件人显示地址（From）</Label>
                          <Input
                            type="email"
                            value={form.smtp_from}
                            onChange={e => set("smtp_from", e.target.value)}
                            placeholder="noreply@yourdomain.com（留空使用用户名）"
                            className="h-9 rounded-xl text-sm font-mono"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <Label className="text-xs font-semibold">SMTP 用户名（账号）</Label>
                          <Input
                            value={form.smtp_user}
                            onChange={e => set("smtp_user", e.target.value)}
                            placeholder="your@email.com"
                            autoComplete="off"
                            className="h-9 rounded-xl text-sm font-mono"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <Label className="text-xs font-semibold">SMTP 密码 / 授权码</Label>
                          <Input
                            type="password"
                            value={form.smtp_pass}
                            onChange={e => set("smtp_pass", e.target.value)}
                            placeholder="密码或应用专用授权码"
                            autoComplete="new-password"
                            className="h-9 rounded-xl text-sm font-mono"
                          />
                          <p className="text-[10px] text-muted-foreground">密码加密保存，GET 接口不返回此字段</p>
                        </div>
                      </div>

                      <div className="p-3 rounded-xl bg-sky-50 dark:bg-sky-950/20 border border-sky-200/50 dark:border-sky-800/30 text-[11px] text-sky-700 dark:text-sky-400 space-y-1">
                        <p className="font-semibold">常见 SMTP 配置参考</p>
                        <p>QQ 邮箱：smtp.qq.com · 端口 465 · SSL · 需开启 SMTP 服务并获取授权码</p>
                        <p>163 邮箱：smtp.163.com · 端口 465 · SSL · 需在邮箱设置中开启并获取授权码</p>
                        <p>Gmail：smtp.gmail.com · 端口 587 · STARTTLS · 需开启两步验证后生成应用密码</p>
                        <p>阿里云邮：smtp.aliyun.com · 端口 465 · SSL</p>
                      </div>
                    </div>
                  </div>

                  {/* Resend fallback info */}
                  <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                    <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400">
                        <RiShieldLine className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-sm font-bold">Resend（备用 / 兜底）</h3>
                    </div>
                    <div className="p-5 space-y-3">
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        当 SMTP 未启用时，系统自动回退到 Resend 发送邮件。配置方式：在 Secrets 中设置以下环境变量。
                      </p>
                      <div className="p-3 rounded-xl bg-muted/40 border border-border/60 text-[11px] text-muted-foreground space-y-1">
                        <p><code className="font-mono">RESEND_API_KEY</code> — Resend API 密钥（必填）</p>
                        <p><code className="font-mono">RESEND_FROM_EMAIL</code> — 发件人地址（如 noreply@yourdomain.com）</p>
                      </div>
                      <p className="text-[11px] text-amber-600 dark:text-amber-400">
                        注意：Resend 免费版每月限 3,000 封，建议配置 SMTP 作为主要发送渠道。
                      </p>
                    </div>
                  </div>

                  {/* Test email */}
                  <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                    <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400">
                        <RiCheckLine className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-sm font-bold">测试邮件发送</h3>
                    </div>
                    <div className="p-5 space-y-3">
                      <p className="text-xs text-muted-foreground">
                        向管理员账号邮箱发送一封测试邮件，验证当前配置是否正常。SMTP 已启用时使用 SMTP，否则使用 Resend。
                        <br />请先保存设置后再测试。
                      </p>
                      {emailOk === true && (
                        <p className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                          <RiCheckLine className="w-3.5 h-3.5" />测试邮件发送成功，请检查收件箱
                        </p>
                      )}
                      {emailOk === false && (
                        <p className="text-xs text-destructive flex items-center gap-1">
                          <RiAlertLine className="w-3.5 h-3.5" />发送失败，请检查 SMTP 配置或 RESEND_API_KEY
                        </p>
                      )}
                      <Button
                        variant="outline"
                        onClick={handleTestEmail}
                        disabled={testingEmail}
                        className="rounded-xl h-9 gap-2"
                      >
                        {testingEmail
                          ? <><RiLoader4Line className="w-4 h-4 animate-spin" />发送中…</>
                          : <><RiMailSendLine className="w-4 h-4" />发送测试邮件</>}
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* CAPTCHA section */}
              {activeSection === "captcha" && (
                <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                  <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                    <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400">
                      <RiFingerprint2Line className="w-3.5 h-3.5" />
                    </div>
                    <h3 className="text-sm font-bold">人机验证 (CAPTCHA)</h3>
                  </div>
                  <div className="p-5 space-y-5">
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      配置注册页面的人机验证组件，防止机器人批量注册。选择服务商并填写密钥后保存即可生效，无需重启。
                    </p>

                    {/* Provider */}
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold block">验证服务商</label>
                      <select
                        value={form.captcha_provider}
                        onChange={e => setForm(f => ({ ...f, captcha_provider: e.target.value }))}
                        className="w-full h-9 px-3 rounded-xl border border-border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition"
                      >
                        <option value="">不启用（关闭人机验证）</option>
                        <option value="turnstile">Cloudflare Turnstile（免费、无感知，推荐）</option>
                        <option value="hcaptcha">hCaptcha（注重隐私）</option>
                      </select>
                      <p className="text-[11px] text-muted-foreground">
                        推荐使用 Cloudflare Turnstile，免费且对用户无感知，注册 →{" "}
                        <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Cloudflare Dashboard</a>
                      </p>
                    </div>

                    {/* Site key */}
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold block">Site Key（公钥，前端使用）</label>
                      <input
                        type="text"
                        value={form.captcha_site_key}
                        onChange={e => setForm(f => ({ ...f, captcha_site_key: e.target.value }))}
                        placeholder="0x4AAAAAAA..."
                        autoComplete="off"
                        className="w-full h-9 px-3 rounded-xl border border-border bg-background text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition"
                      />
                    </div>

                    {/* Secret key */}
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold block">Secret Key（私钥，仅服务端使用）</label>
                      <input
                        type="password"
                        value={form.captcha_secret_key}
                        onChange={e => setForm(f => ({ ...f, captcha_secret_key: e.target.value }))}
                        placeholder="输入 Secret Key（保存后不可查看明文）"
                        autoComplete="new-password"
                        className="w-full h-9 px-3 rounded-xl border border-border bg-background text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition"
                      />
                      <p className="text-[11px] text-muted-foreground">Secret Key 仅用于服务端验证，不会通过公开 API 返回给前端。</p>
                    </div>

                    {form.captcha_provider && (
                      <div className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/20 border border-amber-200/50 dark:border-amber-700/30">
                        <p className="text-xs font-semibold text-amber-700 dark:text-amber-400 mb-1">使用提醒</p>
                        <p className="text-[11px] text-amber-700/80 dark:text-amber-400/80 leading-relaxed">
                          同时填写 Site Key 和 Secret Key 才会启用验证。注册页将在"发送验证码"之后显示 CAPTCHA 组件，通过后方可提交注册。
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Payment Gateway section */}
              {activeSection === "payment" && (
                <div className="space-y-5">
                  <div>
                    <h3 className="text-sm font-bold flex items-center gap-2">
                      <RiBankCardLine className="w-4 h-4 text-violet-500" />支付网关配置
                    </h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      配置支付渠道。敏感 Key（私钥/Secret）务必通过环境变量设置，不要填入此处。
                      <br />公开 Key（Publishable Key / App ID）可在此配置，保存即生效。
                    </p>
                  </div>

                  <div className="space-y-4">
                    <div className="p-4 rounded-xl border border-border space-y-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">Stripe（国际支付）</span>
                        <label className="flex items-center gap-1.5 cursor-pointer text-xs text-muted-foreground ml-auto">
                          <input type="checkbox" checked={!!form.payment_stripe_enabled}
                            onChange={e => setForm(f => ({ ...f, payment_stripe_enabled: e.target.checked ? "1" : "" }))} className="rounded" />
                          启用
                        </label>
                      </div>
                      <div>
                        <Label className="text-xs mb-1 block">Publishable Key（前端公钥，以 pk_ 开头）</Label>
                        <Input value={form.payment_stripe_pk} onChange={e => setForm(f => ({ ...f, payment_stripe_pk: e.target.value }))}
                          placeholder="pk_live_..." className="h-8 text-sm font-mono" />
                      </div>
                      <div className="text-[11px] text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 rounded-lg px-3 py-2 border border-amber-200/50 dark:border-amber-700/30">
                        私钥（Secret Key）请设置环境变量：<code className="font-mono">STRIPE_SECRET_KEY</code>
                        <br />Webhook 签名密钥：<code className="font-mono">STRIPE_WEBHOOK_SECRET</code>
                        <br />Webhook URL：<code className="font-mono">/api/payment/webhook/stripe</code>
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-border space-y-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">虎皮椒（国内聚合）</span>
                        <label className="flex items-center gap-1.5 cursor-pointer text-xs text-muted-foreground ml-auto">
                          <input type="checkbox" checked={!!form.payment_xunhupay_enabled}
                            onChange={e => setForm(f => ({ ...f, payment_xunhupay_enabled: e.target.checked ? "1" : "" }))} className="rounded" />
                          启用
                        </label>
                      </div>
                      <div>
                        <Label className="text-xs mb-1 block">App ID</Label>
                        <Input value={form.payment_xunhupay_appid} onChange={e => setForm(f => ({ ...f, payment_xunhupay_appid: e.target.value }))}
                          placeholder="虎皮椒应用 ID" className="h-8 text-sm font-mono" />
                      </div>
                      <div className="text-[11px] text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 rounded-lg px-3 py-2 border border-amber-200/50 dark:border-amber-700/30">
                        App Secret 请设置环境变量：<code className="font-mono">XUNHUPAY_APP_SECRET</code>
                        <br />Webhook URL：<code className="font-mono">/api/payment/webhook/xunhupay</code>
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-border space-y-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">支付宝官方（个人/个体户/企业均可）</span>
                        <label className="flex items-center gap-1.5 cursor-pointer text-xs text-muted-foreground ml-auto">
                          <input type="checkbox" checked={!!form.payment_alipay_enabled}
                            onChange={e => setForm(f => ({ ...f, payment_alipay_enabled: e.target.checked ? "1" : "" }))} className="rounded" />
                          启用
                        </label>
                      </div>
                      <div>
                        <Label className="text-xs mb-1 block">App ID</Label>
                        <Input value={form.payment_alipay_appid} onChange={e => setForm(f => ({ ...f, payment_alipay_appid: e.target.value }))}
                          placeholder="支付宝开放平台应用 App ID" className="h-8 text-sm font-mono" />
                      </div>
                      <div>
                        <Label className="text-xs mb-1 block">异步通知 URL（留空自动生成）</Label>
                        <Input value={form.payment_alipay_notify_url} onChange={e => setForm(f => ({ ...f, payment_alipay_notify_url: e.target.value }))}
                          placeholder="https://yourdomain.com/api/payment/webhook/alipay" className="h-8 text-sm font-mono" />
                      </div>
                      <div className="text-[11px] text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 rounded-lg px-3 py-2 border border-amber-200/50 dark:border-amber-700/30">
                        应用私钥（RSA2）：环境变量 <code className="font-mono">ALIPAY_PRIVATE_KEY</code>
                        <br />支付宝公钥：<code className="font-mono">ALIPAY_PUBLIC_KEY</code>（用于回调验签）
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-border space-y-3">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold">PayPal（国际支付）</span>
                        <label className="flex items-center gap-1.5 cursor-pointer text-xs text-muted-foreground ml-auto">
                          <input type="checkbox" checked={!!form.payment_paypal_enabled}
                            onChange={e => setForm(f => ({ ...f, payment_paypal_enabled: e.target.checked ? "1" : "" }))} className="rounded" />
                          启用
                        </label>
                      </div>
                      <div>
                        <Label className="text-xs mb-1 block">Client ID（前端公钥）</Label>
                        <Input value={form.payment_paypal_client_id} onChange={e => setForm(f => ({ ...f, payment_paypal_client_id: e.target.value }))}
                          placeholder="PayPal Client ID（以 A 开头）" className="h-8 text-sm font-mono" />
                      </div>
                      <div className="text-[11px] text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 rounded-lg px-3 py-2 border border-amber-200/50 dark:border-amber-700/30">
                        Client Secret：环境变量 <code className="font-mono">PAYPAL_CLIENT_SECRET</code>
                        <br />沙盒测试：设置 <code className="font-mono">PAYPAL_ENV=sandbox</code>
                        <br />Webhook URL：<code className="font-mono">/api/payment/webhook/paypal</code>（可选，用于加强可靠性）
                        <br />Webhook ID（可选）：<code className="font-mono">PAYPAL_WEBHOOK_ID</code>
                        <br />注意：CNY 不支持 PayPal，会自动转换为 USD 收款
                      </div>
                    </div>

                    <div className="p-4 rounded-xl border border-border space-y-3">
                      <h4 className="text-xs font-semibold text-muted-foreground">通用配置</h4>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <Label className="text-xs mb-1 block">默认货币</Label>
                          <select value={form.payment_currency}
                            onChange={e => setForm(f => ({ ...f, payment_currency: e.target.value }))}
                            className="w-full h-8 text-sm rounded-md border border-input bg-background px-2 focus:outline-none">
                            {["CNY","USD","EUR","HKD"].map(c => <option key={c} value={c}>{c}</option>)}
                          </select>
                        </div>
                        <div>
                          <Label className="text-xs mb-1 block">付款成功跳转 URL（留空默认）</Label>
                          <Input value={form.payment_success_url} onChange={e => setForm(f => ({ ...f, payment_success_url: e.target.value }))}
                            placeholder="/dashboard" className="h-8 text-sm" />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Save bar at bottom */}
              <div className="flex items-center gap-3 pt-2 border-t border-border/40">
                <Button onClick={handleSave} disabled={saving} className="rounded-xl h-9 gap-2 font-semibold">
                  {saving ? <><RiLoader4Line className="w-4 h-4 animate-spin" />保存中…</> : <><RiSaveLine className="w-4 h-4" />保存所有设置</>}
                </Button>
                <Button variant="outline" onClick={reset} disabled={saving} className="rounded-xl h-9 gap-2">
                  <RiRefreshLine className="w-4 h-4" />重置默认
                </Button>
                <p className="text-xs text-muted-foreground ml-auto hidden sm:block">保存后设置将实时同步到所有用户页面</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
