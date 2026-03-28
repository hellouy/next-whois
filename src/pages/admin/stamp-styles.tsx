import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { StampPreviewCard, STAMP_CARD_THEMES } from "@/components/stamp-preview-card";

const CARD_THEMES = STAMP_CARD_THEMES;

const STAMPS_TABS = [
  { href: "/admin/stamps",       label: "品牌审核" },
  { href: "/admin/stamp-styles", label: "弹窗样式" },
];

export default function StampStylesPage() {
  const standardThemes = Object.entries(CARD_THEMES).filter(([, t]) => !t.special);
  const specialThemes  = Object.entries(CARD_THEMES).filter(([, t]) => !!t.special);

  const [previewKey, setPreviewKey] = React.useState<string | null>(null);

  const openPreview  = (key: string) => setPreviewKey(key);
  const closePreview = () => setPreviewKey(null);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") closePreview(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const previewTheme = previewKey ? CARD_THEMES[previewKey] : null;

  return (
    <AdminLayout title="品牌管理">
      <PageTabs tabs={STAMPS_TABS} />

      {/* ── Full-size preview overlay (manual close) ── */}
      {previewKey && (
        <div
          className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-black/70 backdrop-blur-sm"
          onClick={closePreview}>
          <div
            className="rounded-[22px] overflow-hidden shadow-2xl"
            style={{width:340}}
            onClick={e => e.stopPropagation()}>
            <StampPreviewCard themeKey={previewKey} />
          </div>
          <div className="mt-5 flex flex-col items-center gap-1.5 select-none">
            <div className="flex items-center gap-2">
              {previewTheme?.special && <span className="text-lg leading-none">{previewTheme.special}</span>}
              <span className="text-white font-bold text-sm">{previewTheme?.label}</span>
              <code className="text-white/40 text-xs font-mono">{previewKey}</code>
            </div>
            <p className="text-white/40 text-xs">点击背景或按 Esc 关闭</p>
          </div>
        </div>
      )}

      <div className="space-y-10 max-w-3xl">

        <div>
          <h1 className="text-xl font-bold">弹窗样式一览</h1>
          <p className="text-sm text-muted-foreground mt-1">
            在「品牌管理」编辑认领时可选择以下样式，点击缩略图可全屏预览真实效果。
          </p>
        </div>

        {/* ── Standard themes ── */}
        <section className="space-y-3">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
            标准配色 · {standardThemes.length} 种
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            {standardThemes.map(([key, t]) => (
              <div key={key} className="space-y-1.5">
                <button className="w-full text-left cursor-pointer rounded-xl overflow-hidden ring-0 hover:ring-2 ring-primary/40 transition-all active:scale-[0.98]"
                  onClick={() => openPreview(key)}>
                  <StampPreviewCard themeKey={key} />
                </button>
                <div className="flex items-center gap-1.5 px-0.5">
                  <p className="text-xs font-semibold">{t.label}</p>
                  <code className="text-[10px] text-muted-foreground/50 font-mono ml-auto">{key}</code>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Special layout themes ── */}
        <section className="space-y-3">
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
            特殊排版 · {specialThemes.length} 种
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {specialThemes.map(([key, t]) => (
              <div key={key} className="space-y-1.5">
                <button className="w-full text-left cursor-pointer rounded-xl overflow-hidden ring-0 hover:ring-2 ring-primary/40 transition-all active:scale-[0.98]"
                  onClick={() => openPreview(key)}>
                  <StampPreviewCard themeKey={key} />
                </button>
                <div className="flex items-center gap-1.5 px-0.5">
                  <span className="text-sm leading-none">{t.special}</span>
                  <p className="text-xs font-semibold">{t.label}</p>
                  <code className="text-[10px] text-muted-foreground/50 font-mono ml-auto">{key}</code>
                </div>
              </div>
            ))}
          </div>
        </section>

      </div>
    </AdminLayout>
  );
}
