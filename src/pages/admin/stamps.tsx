import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiSearchLine, RiDeleteBinLine,
  RiShieldCheckLine, RiShieldLine, RiCalendarLine, RiMailLine,
  RiLinkM, RiFileTextLine, RiUserLine, RiArrowDownSLine,
  RiArrowUpSLine, RiFilterLine, RiPencilLine, RiCloseLine,
  RiSaveLine, RiAddLine, RiGlobalLine, RiPriceTagLine,
  RiIdCardLine, RiBuildingLine, RiAwardLine, RiVipCrownLine,
  RiShakeHandsLine, RiCodeSLine, RiAlertLine, RiEyeLine,
} from "@remixicon/react";
import { StampPreviewCard, STAMP_CARD_THEMES } from "@/components/stamp-preview-card";

const STAMPS_TABS = [
  { href: "/admin/stamps",       label: "品牌审核" },
  { href: "/admin/stamp-styles", label: "弹窗样式" },
];

type Stamp = {
  id: string;
  domain: string;
  tag_name: string;
  tag_style: string;
  card_theme: string;
  link: string | null;
  description: string | null;
  nickname: string;
  email: string;
  verified: boolean;
  verified_at: string | null;
  created_at: string;
};

const TAG_STYLES: { value: string; label: string; color: string; icon: React.ElementType }[] = [
  { value: "personal", label: "个人",   color: "bg-zinc-800 text-white",                                               icon: RiIdCardLine      },
  { value: "official", label: "官方",   color: "bg-blue-700 text-white",                                               icon: RiBuildingLine    },
  { value: "brand",    label: "品牌",   color: "bg-violet-600 text-white",                                             icon: RiAwardLine       },
  { value: "verified", label: "认证",   color: "bg-emerald-500 text-white",                                            icon: RiShieldCheckLine },
  { value: "partner",  label: "合作",   color: "bg-orange-500 text-white",                                             icon: RiShakeHandsLine  },
  { value: "dev",      label: "开发者", color: "bg-slate-800 text-white",                                              icon: RiCodeSLine       },
  { value: "warning",  label: "警告",   color: "bg-amber-500 text-white",                                              icon: RiAlertLine       },
  { value: "premium",  label: "高级",   color: "bg-gradient-to-r from-violet-600 to-fuchsia-500 text-white",           icon: RiVipCrownLine    },
];

function styleColor(style: string) {
  return TAG_STYLES.find(s => s.value === style)?.color ?? "bg-teal-500 text-white";
}

function StyleBadge({ style, name }: { style: string; name?: string }) {
  const ts = TAG_STYLES.find(s => s.value === style);
  const Icon = ts?.icon ?? RiShieldCheckLine;
  return (
    <span className={cn("inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold shrink-0", styleColor(style))}>
      <Icon className="w-3 h-3" />
      {name || ts?.label || style}
    </span>
  );
}

function ThemePreview({ theme }: { theme: string }) {
  const t = STAMP_CARD_THEMES[theme];
  if (!t) return null;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn("inline-block w-5 h-5 rounded-md bg-gradient-to-br shrink-0 border border-white/10", t.hero)} />
      {t.special && <span className="text-[10px]">{t.special}</span>}
      <span className="text-xs font-medium">{t.label}</span>
    </span>
  );
}

function StampFormFields({
  tagName, setTagName, tagStyle, setTagStyle,
  cardTheme, setCardTheme, link, setLink,
  description, setDescription,
  domain, setDomain, nickname, setNickname, email, setEmail,
  showDomainOwner,
  verified, setVerified,
  showVerifiedToggle,
}: {
  tagName: string; setTagName: (v: string) => void;
  tagStyle: string; setTagStyle: (v: string) => void;
  cardTheme: string; setCardTheme: (v: string) => void;
  link: string; setLink: (v: string) => void;
  description: string; setDescription: (v: string) => void;
  domain?: string; setDomain?: (v: string) => void;
  nickname?: string; setNickname?: (v: string) => void;
  email?: string; setEmail?: (v: string) => void;
  showDomainOwner?: boolean;
  verified?: boolean; setVerified?: (v: boolean) => void;
  showVerifiedToggle?: boolean;
}) {
  const [themePickerOpen, setThemePickerOpen] = React.useState(false);

  return (
    <div className="space-y-4">
      {showDomainOwner && setDomain && setNickname && setEmail && (
        <>
          <div className="space-y-1.5">
            <Label className="text-sm font-medium flex items-center gap-1.5">
              <RiGlobalLine className="w-3.5 h-3.5 text-muted-foreground" />域名
            </Label>
            <Input
              value={domain}
              onChange={e => setDomain(e.target.value)}
              placeholder="example.com"
              className="h-10 rounded-xl font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-sm font-medium flex items-center gap-1.5">
                <RiUserLine className="w-3.5 h-3.5 text-muted-foreground" />昵称
              </Label>
              <Input value={nickname} onChange={e => setNickname(e.target.value)}
                placeholder="品牌名称" className="h-10 rounded-xl" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-sm font-medium flex items-center gap-1.5">
                <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />邮箱
              </Label>
              <Input value={email} onChange={e => setEmail(e.target.value)}
                placeholder="admin@example.com" type="email" className="h-10 rounded-xl" />
            </div>
          </div>
          <div className="border-t border-border/50" />
        </>
      )}

      <div className="space-y-1.5">
        <Label className="text-sm font-medium flex items-center gap-1.5">
          <RiPriceTagLine className="w-3.5 h-3.5 text-muted-foreground" />标签文字
        </Label>
        <Input
          value={tagName}
          onChange={e => setTagName(e.target.value)}
          placeholder="例如：官方认证"
          className="h-10 rounded-xl"
          maxLength={20}
        />
      </div>

      <div className="space-y-1.5">
        <Label className="text-sm font-medium">标签样式</Label>
        <div className="grid grid-cols-4 gap-1.5">
          {TAG_STYLES.map(s => {
            const Icon = s.icon;
            const isSelected = tagStyle === s.value;
            return (
              <button
                key={s.value}
                type="button"
                onClick={() => setTagStyle(s.value)}
                className={cn(
                  "relative flex flex-col items-center gap-1 py-2 px-1 rounded-xl border-2 transition-all text-center",
                  isSelected
                    ? "border-foreground/50 shadow-sm scale-[0.97]"
                    : "border-transparent hover:border-border/60"
                )}
              >
                <span className={cn("w-8 h-8 rounded-lg flex items-center justify-center", s.color)}>
                  <Icon className="w-4 h-4" />
                </span>
                <span className="text-[10px] font-semibold leading-none text-foreground/80">{s.label}</span>
                {isSelected && (
                  <span className="absolute top-1 right-1 w-3 h-3 rounded-full bg-foreground flex items-center justify-center">
                    <RiShieldCheckLine className="w-2 h-2 text-background" />
                  </span>
                )}
              </button>
            );
          })}
        </div>
        <div className="flex items-center gap-2 mt-0.5 px-1">
          <span className="text-[11px] text-muted-foreground">当前：</span>
          <StyleBadge style={tagStyle} name={tagName || "标签预览"} />
        </div>
      </div>

      {/* ── Theme picker overlay ── */}
      {themePickerOpen && (
        <div className="fixed inset-0 z-[200] flex flex-col items-stretch" style={{background:"rgba(0,0,0,0.55)", backdropFilter:"blur(4px)"}}>
          <div className="flex-1" onClick={() => setThemePickerOpen(false)} />
          <div className="bg-background rounded-t-2xl shadow-2xl max-h-[82vh] flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
              <div>
                <p className="font-bold text-base">选择弹窗样式</p>
                <p className="text-xs text-muted-foreground mt-0.5">点击样式即可选中并关闭</p>
              </div>
              <button type="button" onClick={() => setThemePickerOpen(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl hover:bg-muted transition-colors text-muted-foreground">
                <RiCloseLine className="w-4 h-4" />
              </button>
            </div>
            {/* Scrollable grid */}
            <div className="overflow-y-auto px-5 py-4 space-y-5">
              {/* Standard themes */}
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-3">标准配色</p>
                <div className="grid grid-cols-3 gap-2.5">
                  {Object.entries(STAMP_CARD_THEMES).filter(([, t]) => !t.special).map(([key, t]) => (
                    <button key={key} type="button"
                      onClick={() => { setCardTheme(key); setThemePickerOpen(false); }}
                      className={cn(
                        "flex flex-col items-center gap-2 p-3 rounded-xl border-2 transition-all active:scale-[0.97]",
                        cardTheme === key
                          ? "border-primary bg-primary/5"
                          : "border-transparent hover:border-border hover:bg-muted/40"
                      )}>
                      <span className={cn("w-full h-7 rounded-lg overflow-hidden", t.hero)} />
                      <span className="text-[11px] font-semibold leading-none">{t.label}</span>
                      {cardTheme === key && (
                        <span className="text-[9px] text-primary font-bold uppercase tracking-widest">已选</span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
              {/* Special layout themes — show actual card previews */}
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-3">特殊排版 <span className="normal-case font-normal opacity-60">· 实际效果预览</span></p>
                <div className="grid grid-cols-2 gap-3">
                  {Object.entries(STAMP_CARD_THEMES).filter(([, t]) => !!t.special).map(([key, t]) => (
                    <button key={key} type="button"
                      onClick={() => { setCardTheme(key); setThemePickerOpen(false); }}
                      className={cn(
                        "flex flex-col gap-2 rounded-xl border-2 overflow-hidden transition-all active:scale-[0.97]",
                        cardTheme === key
                          ? "border-primary"
                          : "border-transparent hover:border-border"
                      )}>
                      <div className="pointer-events-none scale-[0.72] origin-top-left w-[138.8%]">
                        <StampPreviewCard themeKey={key} />
                      </div>
                      <div className={cn(
                        "flex items-center justify-between px-2 pb-2 -mt-[28%]",
                      )}>
                        <span className="text-[11px] font-semibold">{t.special} {t.label}</span>
                        {cardTheme === key && (
                          <span className="text-[9px] text-primary font-bold uppercase tracking-widest">已选</span>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
              <div className="pb-safe pt-1">
                <a href="/admin/stamp-styles" target="_blank"
                  className="block text-center text-[11px] text-muted-foreground hover:text-foreground transition-colors py-2">
                  查看完整效果预览 →
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        <Label className="text-sm font-medium">弹窗样式</Label>
        {/* Clickable display — opens theme picker */}
        {(() => {
          const cur = STAMP_CARD_THEMES[cardTheme];
          return (
            <button type="button" onClick={() => setThemePickerOpen(true)}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl border border-border bg-muted/30 hover:bg-muted/60 transition-colors text-left">
              <span className={cn("w-6 h-6 rounded-md shrink-0 overflow-hidden flex items-center justify-center text-xs", cur?.hero ?? "bg-zinc-700")}>
                {cur?.special && <span className="leading-none">{cur.special}</span>}
              </span>
              <span className="text-sm font-medium flex-1">
                {cur?.label ?? cardTheme}
                {cur?.special && <span className="ml-1.5 text-muted-foreground text-xs font-normal">· 特殊排版</span>}
              </span>
              <span className="text-[11px] text-muted-foreground font-medium shrink-0">点击更换 ›</span>
            </button>
          );
        })()}
      </div>

      <div className="space-y-1.5">
        <Label className="text-sm font-medium flex items-center gap-1.5">
          <RiLinkM className="w-3.5 h-3.5 text-muted-foreground" />官网链接
          <span className="text-[10px] text-muted-foreground/60 ml-auto">可选</span>
        </Label>
        <Input value={link} onChange={e => setLink(e.target.value)}
          placeholder="https://example.com" type="url" className="h-10 rounded-xl" />
      </div>

      <div className="space-y-1.5">
        <Label className="text-sm font-medium flex items-center gap-1.5">
          <RiFileTextLine className="w-3.5 h-3.5 text-muted-foreground" />简介说明
          <span className="text-[10px] text-muted-foreground/60 ml-auto">可选</span>
        </Label>
        <textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="品牌或组织的简要说明…"
          rows={2}
          maxLength={200}
          className="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <p className="text-[10px] text-muted-foreground text-right">{description.length}/200</p>
      </div>

      {/* ── Live popup preview ── */}
      {tagName && (
        <div>
          <div className="flex items-center gap-2 mb-2.5">
            <RiEyeLine className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">弹窗实际效果</span>
            <div className="flex-1 h-px bg-border/50" />
          </div>
          <div className="rounded-2xl overflow-hidden shadow-sm border border-border/30">
            <StampPreviewCard
              themeKey={cardTheme || "app"}
              data={{
                tagName,
                domain: domain || undefined,
                description: description || undefined,
                link: link || undefined,
                tagLabel: TAG_STYLES.find(s => s.value === tagStyle)?.label,
                icon: TAG_STYLES.find(s => s.value === tagStyle)?.icon,
              }}
            />
          </div>
        </div>
      )}

      {showVerifiedToggle && setVerified && (
        <label className="flex items-center gap-3 cursor-pointer select-none p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200/60 dark:border-emerald-800/40">
          <input
            type="checkbox"
            checked={verified}
            onChange={e => setVerified(e.target.checked)}
            className="w-4 h-4 accent-emerald-500"
          />
          <div>
            <p className="text-sm font-medium text-emerald-800 dark:text-emerald-300">直接标记为已认证</p>
            <p className="text-[11px] text-emerald-600/80 dark:text-emerald-400/60">无需用户进行 DNS 或文件验证</p>
          </div>
        </label>
      )}
    </div>
  );
}

function StampCreateModal({ onClose, onCreated }: {
  onClose: () => void;
  onCreated: (stamp: Stamp) => void;
}) {
  const [domain, setDomain] = React.useState("");
  const [nickname, setNickname] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [tagName, setTagName] = React.useState("官方认证");
  const [tagStyle, setTagStyle] = React.useState("official");
  const [cardTheme, setCardTheme] = React.useState("app");
  const [link, setLink] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [verified, setVerified] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  async function handleCreate() {
    if (!domain.trim()) { toast.error("域名不能为空"); return; }
    if (!tagName.trim()) { toast.error("标签文字不能为空"); return; }
    if (!nickname.trim()) { toast.error("昵称不能为空"); return; }
    if (!email.trim()) { toast.error("邮箱不能为空"); return; }
    setSaving(true);
    try {
      const res = await fetch("/api/admin/stamps", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: domain.trim(),
          tag_name: tagName.trim(),
          tag_style: tagStyle,
          card_theme: cardTheme,
          link: link.trim() || null,
          description: description.trim() || null,
          nickname: nickname.trim(),
          email: email.trim(),
          verified,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(`印章 ${domain.trim()} 已创建`);
      onCreated(data.stamp);
      onClose();
    } catch (e: any) {
      toast.error(e.message || "创建失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-background border border-border rounded-2xl shadow-xl w-full max-w-lg flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between p-6 pb-4 shrink-0">
          <div>
            <h3 className="text-base font-bold">新建品牌印章</h3>
            <p className="text-xs text-muted-foreground mt-0.5">直接创建认证印章，无需用户提交申请</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-4 h-4" />
          </button>
        </div>
        <div className="overflow-y-auto px-6 pb-2 flex-1">
          <StampFormFields
            tagName={tagName} setTagName={setTagName}
            tagStyle={tagStyle} setTagStyle={setTagStyle}
            cardTheme={cardTheme} setCardTheme={setCardTheme}
            link={link} setLink={setLink}
            description={description} setDescription={setDescription}
            domain={domain} setDomain={setDomain}
            nickname={nickname} setNickname={setNickname}
            email={email} setEmail={setEmail}
            showDomainOwner
            verified={verified} setVerified={setVerified}
            showVerifiedToggle
          />
        </div>
        <div className="flex items-center gap-3 p-6 pt-4 border-t border-border/50 shrink-0">
          <Button onClick={handleCreate} disabled={saving} className="flex-1 rounded-xl h-10 gap-2">
            {saving
              ? <><RiLoader4Line className="w-4 h-4 animate-spin" />创建中…</>
              : <><RiAddLine className="w-4 h-4" />创建印章</>
            }
          </Button>
          <Button variant="outline" onClick={onClose} disabled={saving} className="rounded-xl h-10">取消</Button>
        </div>
      </div>
    </div>
  );
}

function StampEditModal({ stamp, onClose, onSaved }: {
  stamp: Stamp;
  onClose: () => void;
  onSaved: (updated: Stamp) => void;
}) {
  const [tagName, setTagName] = React.useState(stamp.tag_name);
  const [tagStyle, setTagStyle] = React.useState(stamp.tag_style);
  const [cardTheme, setCardTheme] = React.useState(stamp.card_theme || "app");
  const [link, setLink] = React.useState(stamp.link || "");
  const [description, setDescription] = React.useState(stamp.description || "");
  const [saving, setSaving] = React.useState(false);

  async function handleSave() {
    if (!tagName.trim()) { toast.error("标签名不能为空"); return; }
    setSaving(true);
    try {
      const res = await fetch(`/api/admin/stamps?id=${stamp.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tag_name: tagName.trim(),
          tag_style: tagStyle,
          card_theme: cardTheme,
          link: link.trim() || null,
          description: description.trim() || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success("品牌信息已更新");
      onSaved(data.stamp);
      onClose();
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-background border border-border rounded-2xl shadow-xl w-full max-w-lg flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between p-6 pb-4 shrink-0">
          <div>
            <h3 className="text-base font-bold">编辑品牌标签</h3>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono">{stamp.domain}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-4 h-4" />
          </button>
        </div>
        <div className="overflow-y-auto px-6 pb-2 flex-1">
          <StampFormFields
            tagName={tagName} setTagName={setTagName}
            tagStyle={tagStyle} setTagStyle={setTagStyle}
            cardTheme={cardTheme} setCardTheme={setCardTheme}
            link={link} setLink={setLink}
            description={description} setDescription={setDescription}
          />
        </div>
        <div className="flex items-center gap-3 p-6 pt-4 border-t border-border/50 shrink-0">
          <Button onClick={handleSave} disabled={saving} className="flex-1 rounded-xl h-10 gap-2">
            {saving
              ? <><RiLoader4Line className="w-4 h-4 animate-spin" />保存中…</>
              : <><RiSaveLine className="w-4 h-4" />保存更改</>
            }
          </Button>
          <Button variant="outline" onClick={onClose} disabled={saving} className="rounded-xl h-10">取消</Button>
        </div>
      </div>
    </div>
  );
}

type StatusFilter = "all" | "pending" | "verified";

export default function AdminStampsPage() {
  const [stamps, setStamps] = React.useState<Stamp[]>([]);
  const [total, setTotal] = React.useState(0);
  const [verifiedCount, setVerifiedCount] = React.useState(0);
  const [pendingCount, setPendingCount] = React.useState(0);
  const [styleCounts, setStyleCounts] = React.useState<{ tag_style: string; count: string }[]>([]);
  const [search, setSearch] = React.useState("");
  const [statusFilter, setStatusFilter] = React.useState<StatusFilter>("all");
  const [styleFilter, setStyleFilter] = React.useState("all");
  const [loading, setLoading] = React.useState(false);
  const [acting, setActing] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const [editStamp, setEditStamp] = React.useState<Stamp | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [offset, setOffset] = React.useState(0);
  const LIMIT = 50;

  function load(q: string, sf: StatusFilter, style: string, off = 0) {
    setLoading(true);
    fetch(`/api/admin/stamps?search=${encodeURIComponent(q)}&filter=${sf}&style=${style}&limit=${LIMIT}&offset=${off}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) { toast.error(data.error); return; }
        setStamps(off === 0 ? data.stamps || [] : prev => [...prev, ...(data.stamps || [])]);
        setTotal(data.total || 0);
        setVerifiedCount(data.verifiedCount || 0);
        setPendingCount(data.pendingCount || 0);
        setStyleCounts(data.styleCounts || []);
        setOffset(off);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load("", "all", "all", 0); }, []);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setOffset(0);
    load(search, statusFilter, styleFilter, 0);
  }

  function handleStatusFilter(f: StatusFilter) {
    setStatusFilter(f);
    setOffset(0);
    load(search, f, styleFilter, 0);
  }

  function handleStyleFilter(style: string) {
    setStyleFilter(style);
    setOffset(0);
    load(search, statusFilter, style, 0);
  }

  async function toggleVerify(stamp: Stamp) {
    setActing(stamp.id);
    try {
      const res = await fetch(`/api/admin/stamps?id=${stamp.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verified: !stamp.verified }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStamps(prev => prev.map(s => s.id === stamp.id ? { ...s, ...data.stamp } : s));
      if (!stamp.verified) { setVerifiedCount(v => v + 1); setPendingCount(v => v - 1); }
      else { setVerifiedCount(v => v - 1); setPendingCount(v => v + 1); }
      toast.success(stamp.verified ? "已撤销认证" : "已认证");
    } catch (e: any) {
      toast.error(e.message || "操作失败");
    } finally {
      setActing(null);
    }
  }

  async function deleteStamp(id: string, domain: string) {
    if (!confirm(`确定要删除 ${domain} 的品牌印章吗？此操作不可撤销。`)) return;
    setActing(id);
    try {
      const res = await fetch(`/api/admin/stamps?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error((await res.json()).error);
      setStamps(prev => prev.filter(s => s.id !== id));
      setTotal(prev => prev - 1);
      toast.success("已删除");
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setActing(null);
    }
  }

  function fmt(d: string | null) {
    if (!d) return "—";
    return new Date(d).toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
  }

  const STATUS_FILTERS: { key: StatusFilter; label: string; count: number }[] = [
    { key: "all",     label: "全部",   count: verifiedCount + pendingCount },
    { key: "pending", label: "待审核", count: pendingCount },
    { key: "verified",label: "已认证", count: verifiedCount },
  ];

  const styleTotal = styleCounts.reduce((acc, s) => acc + parseInt(s.count), 0);

  return (
    <AdminLayout title="品牌印章">
      {creating && (
        <StampCreateModal
          onClose={() => setCreating(false)}
          onCreated={stamp => {
            setStamps(prev => [stamp, ...prev]);
            setTotal(prev => prev + 1);
            if (stamp.verified) setVerifiedCount(v => v + 1);
            else setPendingCount(v => v + 1);
          }}
        />
      )}
      {editStamp && (
        <StampEditModal
          stamp={editStamp}
          onClose={() => setEditStamp(null)}
          onSaved={updated => setStamps(prev => prev.map(s => s.id === updated.id ? { ...s, ...updated } : s))}
        />
      )}

      <div className="space-y-5">
        <PageTabs tabs={STAMPS_TABS} />
        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">品牌印章管理</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              共 {total.toLocaleString()} 条 · 已认证 {verifiedCount} · 待审核 {pendingCount}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <form onSubmit={handleSearch} className="flex items-center gap-2">
              <div className="relative">
                <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
                <Input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="域名、标签、邮箱…"
                  className="pl-8 h-9 rounded-xl text-sm w-44"
                />
              </div>
              <Button type="submit" size="sm" className="h-9 rounded-xl px-3">搜索</Button>
            </form>
            <Button
              size="sm"
              onClick={() => setCreating(true)}
              className="h-9 rounded-xl px-3 gap-1.5"
            >
              <RiAddLine className="w-4 h-4" />新建印章
            </Button>
          </div>
        </div>

        {/* Sub-category by style */}
        <div className="glass-panel border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <RiPriceTagLine className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">按印章分类</span>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleStyleFilter("all")}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
                styleFilter === "all"
                  ? "bg-foreground text-background border-foreground"
                  : "border-border text-muted-foreground hover:text-foreground hover:border-foreground/40"
              )}
            >
              全部
              <span className="text-[10px] opacity-70">{styleTotal}</span>
            </button>
            {TAG_STYLES.map(s => {
              const count = parseInt(styleCounts.find(c => c.tag_style === s.value)?.count ?? "0");
              return (
                <button
                  key={s.value}
                  onClick={() => handleStyleFilter(s.value)}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border-2 transition-all",
                    s.color,
                    styleFilter === s.value
                      ? "border-foreground/60 scale-[0.97]"
                      : "opacity-60 border-transparent hover:opacity-90"
                  )}
                >
                  {s.label}
                  {count > 0 && <span className="text-[10px] bg-white/25 px-1 rounded">{count}</span>}
                </button>
              );
            })}
          </div>
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-1.5 p-1 glass-panel border border-border rounded-xl w-fit">
          <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground ml-1" />
          {STATUS_FILTERS.map(f => (
            <button
              key={f.key}
              onClick={() => handleStatusFilter(f.key)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all",
                statusFilter === f.key
                  ? "bg-primary text-primary-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              {f.label}
              {f.count > 0 && (
                <span className={cn(
                  "ml-1.5 text-[10px] px-1 py-0.5 rounded",
                  statusFilter === f.key ? "bg-white/20" : "bg-muted-foreground/10"
                )}>{f.count}</span>
              )}
            </button>
          ))}
        </div>

        {/* List */}
        {loading && offset === 0 ? (
          <div className="flex justify-center py-12">
            <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : stamps.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <RiShieldCheckLine className="w-10 h-10 text-muted-foreground/30 mx-auto" />
            <p className="text-sm text-muted-foreground">没有找到记录</p>
            <Button size="sm" variant="outline" className="rounded-xl h-8 gap-1.5 mt-2" onClick={() => setCreating(true)}>
              <RiAddLine className="w-3.5 h-3.5" />新建第一个印章
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            {stamps.map(stamp => {
              const isExpanded = expanded === stamp.id;
              const hasDetails = stamp.link || stamp.description || stamp.nickname || stamp.email;
              return (
                <div
                  key={stamp.id}
                  className={cn(
                    "glass-panel border rounded-xl overflow-hidden group transition-colors",
                    stamp.verified
                      ? "border-emerald-200/60 dark:border-emerald-800/30"
                      : "border-border"
                  )}
                >
                  <div className="p-4 flex items-center gap-3">
                    <div className={cn(
                      "w-8 h-8 rounded-full flex items-center justify-center shrink-0",
                      stamp.verified ? "bg-emerald-100 dark:bg-emerald-950/40" : "bg-muted"
                    )}>
                      {stamp.verified
                        ? <RiShieldCheckLine className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                        : <RiShieldLine className="w-4 h-4 text-muted-foreground" />
                      }
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold font-mono">{stamp.domain}</p>
                        <StyleBadge style={stamp.tag_style} name={stamp.tag_name} />
                        <ThemePreview theme={stamp.card_theme} />
                        {stamp.verified
                          ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold">已认证</span>
                          : <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-semibold">待审核</span>
                        }
                      </div>
                      <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          <RiUserLine className="w-3 h-3" />{stamp.nickname}
                        </span>
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          <RiMailLine className="w-3 h-3" />{stamp.email}
                        </span>
                        <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                          <RiCalendarLine className="w-3 h-3" />{fmt(stamp.created_at)}
                        </span>
                        {stamp.verified && stamp.verified_at && (
                          <span className="text-[10px] text-emerald-600 dark:text-emerald-400">
                            认证于 {fmt(stamp.verified_at)}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => setEditStamp(stamp)}
                        className="p-1.5 rounded-lg text-muted-foreground hover:bg-blue-50 dark:hover:bg-blue-950/30 hover:text-blue-500 transition-colors"
                        title="编辑"
                      >
                        <RiPencilLine className="w-3.5 h-3.5" />
                      </button>
                      {hasDetails && (
                        <button
                          onClick={() => setExpanded(isExpanded ? null : stamp.id)}
                          className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted transition-colors"
                          title={isExpanded ? "收起" : "展开详情"}
                        >
                          {isExpanded
                            ? <RiArrowUpSLine className="w-3.5 h-3.5" />
                            : <RiArrowDownSLine className="w-3.5 h-3.5" />
                          }
                        </button>
                      )}
                      <button
                        onClick={() => toggleVerify(stamp)}
                        disabled={acting === stamp.id}
                        className={cn(
                          "px-2.5 py-1.5 rounded-lg text-[11px] font-semibold transition-colors",
                          stamp.verified
                            ? "bg-muted text-muted-foreground hover:bg-amber-50 dark:hover:bg-amber-950/30 hover:text-amber-600"
                            : "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-100"
                        )}
                      >
                        {acting === stamp.id
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : stamp.verified ? "撤销" : "认证通过"
                        }
                      </button>
                      <button
                        onClick={() => deleteStamp(stamp.id, stamp.domain)}
                        disabled={acting === stamp.id}
                        className="p-1.5 rounded-lg text-muted-foreground hover:bg-red-50 dark:hover:bg-red-950/30 hover:text-red-500 transition-colors"
                        title="删除"
                      >
                        <RiDeleteBinLine className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="border-t border-border/50 px-4 py-3 bg-muted/20 space-y-2">
                      {stamp.link && (
                        <div className="flex items-start gap-2">
                          <RiLinkM className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
                          <a href={stamp.link} target="_blank" rel="noopener noreferrer"
                            className="text-xs text-primary hover:underline break-all">{stamp.link}</a>
                        </div>
                      )}
                      {stamp.description && (
                        <div className="flex items-start gap-2">
                          <RiFileTextLine className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
                          <p className="text-xs text-foreground/80">{stamp.description}</p>
                        </div>
                      )}
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-[10px] text-muted-foreground font-mono">ID: {stamp.id}</span>
                        <span className="text-[10px] text-muted-foreground">
                          样式: <span className="font-medium">{stamp.tag_style}</span>
                        </span>
                        <span className="text-[10px] text-muted-foreground">
                          主题: <span className="font-medium">{stamp.card_theme || "app"}</span>
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {stamps.length < total && (
              <div className="text-center py-3">
                <Button
                  variant="outline" size="sm" disabled={loading}
                  onClick={() => load(search, statusFilter, styleFilter, offset + LIMIT)}
                  className="rounded-xl h-9 gap-2"
                >
                  {loading ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : null}
                  加载更多（还有 {total - stamps.length} 条）
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
