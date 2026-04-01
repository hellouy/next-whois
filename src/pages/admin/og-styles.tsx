import React from "react";
import Head from "next/head";
import { GetServerSideProps } from "next";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  RiLoader4Line,
  RiSaveLine,
  RiRefreshLine,
  RiCheckLine,
  RiCloseLine,
  RiImageLine,
  RiEyeLine,
  RiMoonLine,
  RiSunLine,
  RiShuffleLine,
  RiFlipHorizontalLine,
  RiPencilLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { isAdmin } from "@/lib/admin";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many } from "@/lib/db-query";
import { cn } from "@/lib/utils";
const DEFAULT_BRAND_NAME = "RDAP+WHOIS";
const DEFAULT_TAGLINE    = "WHOIS / RDAP · Domain Lookup Tool";

const TOTAL_STYLES = 8;

const STYLE_META: { id: number; name: string; desc: string; emoji: string }[] =
  [
    {
      id: 0,
      name: "极简网格",
      desc: "点阵背景，域名居中，两端页脚",
      emoji: "◎",
    },
    {
      id: 1,
      name: "渐变侧栏",
      desc: "蓝紫渐变左列，右侧大字",
      emoji: "▌",
    },
    {
      id: 2,
      name: "终端暗色",
      desc: "全黑终端风，等宽字体，绿色标签",
      emoji: ">_",
    },
    {
      id: 3,
      name: "品牌顶栏",
      desc: "蓝色全宽顶栏，内容居中",
      emoji: "▀",
    },
    {
      id: 4,
      name: "极致留白",
      desc: "极深底色，顶部蓝线，超大字体",
      emoji: "─",
    },
    {
      id: 5,
      name: "工程蓝图",
      desc: "深蓝网格，青色标注，四角标记",
      emoji: "⊹",
    },
    {
      id: 6,
      name: "报刊版式",
      desc: "米白底色，黑色边框，全大写",
      emoji: "▦",
    },
    {
      id: 7,
      name: "类型渐变",
      desc: "按查询类型变色，全白文字",
      emoji: "◈",
    },
  ];

interface Props {
  initialEnabledStyles: number[];
  initialBrandName: string;
  initialTagline: string;
}

export const getServerSideProps: GetServerSideProps<Props> = async (ctx) => {
  const session = await getServerSession(ctx.req, ctx.res, authOptions);
  if (!isAdmin((session?.user as any)?.email)) {
    return { redirect: { destination: "/login", permanent: false } };
  }

  try {
    const rows = await many<{ key: string; value: string }>(
      "SELECT key, value FROM site_settings WHERE key IN ('og_enabled_styles','og_brand_name','og_tagline')",
    );
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;

    const raw = map.og_enabled_styles || "";
    const parsed = raw
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n) && n >= 0 && n < TOTAL_STYLES);
    const enabled =
      parsed.length > 0
        ? parsed
        : Array.from({ length: TOTAL_STYLES }, (_, i) => i);

    return {
      props: {
        initialEnabledStyles: enabled,
        initialBrandName: map.og_brand_name || DEFAULT_BRAND_NAME,
        initialTagline: map.og_tagline || DEFAULT_TAGLINE,
      },
    };
  } catch {
    return {
      props: {
        initialEnabledStyles: Array.from({ length: TOTAL_STYLES }, (_, i) => i),
        initialBrandName: DEFAULT_BRAND_NAME,
        initialTagline: DEFAULT_TAGLINE,
      },
    };
  }
};

export default function OgStylesPage({ initialEnabledStyles, initialBrandName, initialTagline }: Props) {
  const [enabled, setEnabled] = React.useState<Set<number>>(
    new Set(initialEnabledStyles),
  );
  const [savedEnabled, setSavedEnabled] = React.useState<Set<number>>(
    new Set(initialEnabledStyles),
  );
  const [saving, setSaving] = React.useState(false);
  const [previewTheme, setPreviewTheme] = React.useState<"light" | "dark">(
    "dark",
  );
  const [previewQuery, setPreviewQuery] = React.useState("example.com");
  const [loadedImages, setLoadedImages] = React.useState<
    Record<number, boolean>
  >({});
  const [errorImages, setErrorImages] = React.useState<
    Record<number, boolean>
  >({});
  const [imgKey, setImgKey] = React.useState(0);

  // Text customization
  const [brandName, setBrandName] = React.useState(initialBrandName);
  const [tagline, setTagline] = React.useState(initialTagline);
  const [savedBrandName, setSavedBrandName] = React.useState(initialBrandName);
  const [savedTagline, setSavedTagline] = React.useState(initialTagline);
  const [savingText, setSavingText] = React.useState(false);

  const hasUnsavedText = brandName !== savedBrandName || tagline !== savedTagline;

  const hasUnsaved = React.useMemo(() => {
    if (enabled.size !== savedEnabled.size) return true;
    for (const id of enabled) {
      if (!savedEnabled.has(id)) return true;
    }
    return false;
  }, [enabled, savedEnabled]);

  function toggle(id: number) {
    setEnabled((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        if (next.size <= 1) {
          toast.error("至少需要保留一种样式");
          return prev;
        }
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  function selectAll() {
    setEnabled(new Set(Array.from({ length: TOTAL_STYLES }, (_, i) => i)));
  }

  function selectNone() {
    const sorted = Array.from(enabled).sort((a, b) => a - b);
    if (sorted.length <= 1) {
      toast.error("至少需要保留一种样式");
      return;
    }
    setEnabled(new Set([sorted[0]]));
  }

  function invertSelection() {
    const all = Array.from({ length: TOTAL_STYLES }, (_, i) => i);
    const inverted = all.filter((id) => !enabled.has(id));
    if (inverted.length === 0) {
      toast.error("至少需要保留一种样式");
      return;
    }
    setEnabled(new Set(inverted));
  }

  function retryImage(id: number) {
    setErrorImages((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
    setLoadedImages((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
    setImgKey((k) => k + 1);
  }

  function refreshPreviews() {
    setLoadedImages({});
    setErrorImages({});
    setImgKey((k) => k + 1);
  }

  async function save() {
    setSaving(true);
    try {
      const sorted = Array.from(enabled).sort((a, b) => a - b);
      const value = sorted.join(",");
      const res = await fetch("/api/admin/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ og_enabled_styles: value }),
      });
      if (!res.ok) throw new Error("保存失败");
      setSavedEnabled(new Set(enabled));
      toast.success(`已保存 OG 样式配置（${sorted.length} 种启用）`);
    } catch {
      toast.error("保存失败，请重试");
    } finally {
      setSaving(false);
    }
  }

  async function saveText() {
    setSavingText(true);
    try {
      const res = await fetch("/api/og-config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ brand_name: brandName, tagline }),
      });
      if (!res.ok) throw new Error("保存失败");
      setSavedBrandName(brandName);
      setSavedTagline(tagline);
      refreshPreviews();
      toast.success("OG 图片文字已保存，预览已刷新");
    } catch {
      toast.error("保存失败，请重试");
    } finally {
      setSavingText(false);
    }
  }

  const previewUrl = (id: number) =>
    `/api/og?style=${id}&query=${encodeURIComponent(previewQuery)}&theme=${previewTheme}&preview=1&_k=${imgKey}`;

  const enabledCount = enabled.size;

  return (
    <AdminLayout title="OG 卡片样式">
      <Head>
        <title>OG 卡片样式 · 管理后台</title>
      </Head>

      <div className="max-w-5xl mx-auto space-y-6 pb-10">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold">OG 卡片样式</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              管理动态 Open Graph 图片的视觉风格，已启用{" "}
              <span className="font-semibold text-foreground">
                {enabledCount}
              </span>{" "}
              / {TOTAL_STYLES} 种，默认按域名哈希随机选取
            </p>
          </div>
          <div className="flex items-center gap-2">
            {hasUnsaved && (
              <span className="text-xs text-amber-600 dark:text-amber-400 font-medium px-2">
                未保存更改
              </span>
            )}
            <Button
              onClick={save}
              disabled={saving}
              className="gap-2"
            >
              {saving ? (
                <RiLoader4Line className="size-4 animate-spin" />
              ) : (
                <RiSaveLine className="size-4" />
              )}
              保存配置
            </Button>
          </div>
        </div>

        {/* ── Text customization panel ── */}
        <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <RiPencilLine className="size-4 text-muted-foreground" />
              <span className="text-sm font-semibold">图片文字内容</span>
              <span className="text-xs text-muted-foreground">（品牌名 · 标语，显示在所有样式的 OG 图片中）</span>
            </div>
            {hasUnsavedText && (
              <span className="text-xs text-amber-600 dark:text-amber-400 font-medium">未保存</span>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">品牌名称</Label>
              <Input
                value={brandName}
                onChange={e => setBrandName(e.target.value)}
                placeholder={DEFAULT_BRAND_NAME}
                className="h-9 rounded-xl font-mono text-sm"
                maxLength={40}
              />
              <p className="text-[10px] text-muted-foreground px-0.5">显示在图片角落或顶栏，如：RDAP+WHOIS</p>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">标语 / 副标题</Label>
              <Input
                value={tagline}
                onChange={e => setTagline(e.target.value)}
                placeholder={DEFAULT_TAGLINE}
                className="h-9 rounded-xl text-sm"
                maxLength={80}
              />
              <p className="text-[10px] text-muted-foreground px-0.5">显示在图片中的辅助说明文字</p>
            </div>
          </div>
          <div className="flex items-center gap-2 justify-end">
            {(brandName !== initialBrandName || tagline !== initialTagline) && (
              <button
                onClick={() => { setBrandName(initialBrandName); setTagline(initialTagline); }}
                className="text-xs text-muted-foreground hover:text-foreground transition-colors px-2"
              >
                还原
              </button>
            )}
            <Button
              size="sm"
              onClick={saveText}
              disabled={savingText || !hasUnsavedText}
              className="gap-1.5 h-8 rounded-xl"
            >
              {savingText ? <RiLoader4Line className="size-3.5 animate-spin" /> : <RiSaveLine className="size-3.5" />}
              保存文字
            </Button>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap p-4 bg-muted/40 rounded-xl border border-border">
          <RiEyeLine className="size-4 text-muted-foreground shrink-0" />
          <span className="text-sm text-muted-foreground">预览设置：</span>

          <input
            className="border border-border rounded-md px-3 py-1.5 text-sm bg-background w-44 focus:outline-none focus:ring-2 focus:ring-ring"
            placeholder="预览域名"
            value={previewQuery}
            onChange={(e) => setPreviewQuery(e.target.value)}
          />

          <button
            onClick={() =>
              setPreviewTheme((t) => (t === "dark" ? "light" : "dark"))
            }
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm border transition-colors",
              "border-border hover:bg-accent",
            )}
          >
            {previewTheme === "dark" ? (
              <RiMoonLine className="size-3.5" />
            ) : (
              <RiSunLine className="size-3.5" />
            )}
            {previewTheme === "dark" ? "深色" : "浅色"}
          </button>

          <button
            onClick={refreshPreviews}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm border border-border hover:bg-accent transition-colors"
          >
            <RiRefreshLine className="size-3.5" />
            刷新预览
          </button>

          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={selectAll}
              className="text-xs text-muted-foreground hover:text-foreground transition-colors px-2"
            >
              全选
            </button>
            <span className="text-muted-foreground/40 text-xs">|</span>
            <button
              onClick={invertSelection}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors px-2"
            >
              <RiFlipHorizontalLine className="size-3" />
              反选
            </button>
            <span className="text-muted-foreground/40 text-xs">|</span>
            <button
              onClick={selectNone}
              className="text-xs text-muted-foreground hover:text-foreground transition-colors px-2"
            >
              仅保留最小
            </button>
          </div>
        </div>

        {enabledCount === 1 && (
          <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400 text-sm">
            <RiShuffleLine className="size-4 shrink-0" />
            当前仅启用 1 种样式，所有查询将固定使用该样式（无随机）
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          {STYLE_META.map((meta) => {
            const isOn = enabled.has(meta.id);
            const loaded = loadedImages[meta.id];
            const errored = errorImages[meta.id];
            return (
              <div
                key={meta.id}
                className={cn(
                  "rounded-xl border-2 overflow-hidden transition-all duration-200 cursor-pointer group",
                  isOn
                    ? "border-primary ring-2 ring-primary/20"
                    : "border-border opacity-60 hover:opacity-80",
                )}
                onClick={() => toggle(meta.id)}
              >
                <div className="relative bg-muted/30 aspect-[1200/630]">
                  {!loaded && !errored && (
                    <div className="absolute inset-0 flex items-center justify-center">
                      <RiLoader4Line className="size-6 text-muted-foreground animate-spin" />
                    </div>
                  )}
                  {errored && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-muted-foreground">
                      <RiImageLine className="size-8 opacity-40" />
                      <span className="text-xs opacity-60">预览加载失败</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          retryImage(meta.id);
                        }}
                        className="flex items-center gap-1 text-xs border border-border rounded-md px-2 py-1 hover:bg-accent transition-colors mt-1"
                      >
                        <RiRefreshLine className="size-3" />
                        重试
                      </button>
                    </div>
                  )}
                  <img
                    src={previewUrl(meta.id)}
                    alt={`样式 ${meta.id} 预览`}
                    className={cn(
                      "w-full h-full object-cover transition-opacity duration-300",
                      loaded ? "opacity-100" : "opacity-0",
                    )}
                    onLoad={() =>
                      setLoadedImages((prev) => ({ ...prev, [meta.id]: true }))
                    }
                    onError={() =>
                      setErrorImages((prev) => ({ ...prev, [meta.id]: true }))
                    }
                  />

                  <div className="absolute top-2 left-2">
                    <span className="bg-background/80 backdrop-blur-sm text-foreground text-[10px] font-bold px-2 py-0.5 rounded-full border border-border">
                      #{meta.id}
                    </span>
                  </div>

                  <div
                    className={cn(
                      "absolute top-2 right-2 size-6 rounded-full flex items-center justify-center transition-colors",
                      isOn
                        ? "bg-primary text-primary-foreground"
                        : "bg-background/80 backdrop-blur-sm border border-border text-muted-foreground",
                    )}
                  >
                    {isOn ? (
                      <RiCheckLine className="size-3.5" />
                    ) : (
                      <RiCloseLine className="size-3.5" />
                    )}
                  </div>
                </div>

                <div className="px-4 py-3 flex items-center justify-between gap-3 bg-background">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="text-base shrink-0 select-none">
                      {meta.emoji}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">
                        {meta.name}
                      </p>
                      <p className="text-xs text-muted-foreground truncate">
                        {meta.desc}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toggle(meta.id);
                    }}
                    className={cn(
                      "shrink-0 px-3 py-1 rounded-md text-xs font-semibold transition-colors",
                      isOn
                        ? "bg-primary/10 text-primary hover:bg-destructive/10 hover:text-destructive"
                        : "bg-muted text-muted-foreground hover:bg-primary/10 hover:text-primary",
                    )}
                  >
                    {isOn ? "已启用" : "已停用"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex justify-end items-center gap-3 pt-2">
          {hasUnsaved && (
            <span className="text-xs text-amber-600 dark:text-amber-400 font-medium">
              有未保存的更改
            </span>
          )}
          <Button onClick={save} disabled={saving} className="gap-2">
            {saving ? (
              <RiLoader4Line className="size-4 animate-spin" />
            ) : (
              <RiSaveLine className="size-4" />
            )}
            保存配置
          </Button>
        </div>
      </div>
    </AdminLayout>
  );
}
