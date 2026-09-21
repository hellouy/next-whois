/** Shared form primitives used across admin settings pages and tabs. */
import React from "react";
import { useRouter } from "next/router";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import {
  RiAddLine, RiDeleteBinLine, RiEyeLine, RiEyeOffLine, RiPaletteLine,
  RiToggleLine, RiToggleFill,
} from "@remixicon/react";

/** Warns the admin before leaving a settings page with unsaved changes. */
export function useUnsavedGuard(dirty: boolean) {
  const router = useRouter();

  React.useEffect(() => {
    if (!dirty) return;
    function onBeforeUnload(e: BeforeUnloadEvent) {
      e.preventDefault();
      e.returnValue = "";
    }
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [dirty]);

  React.useEffect(() => {
    if (!dirty) return;
    function onRouteChange(href: string) {
      if (!window.confirm("有未保存的修改，确认离开？")) {
        router.events.emit("routeChangeError");
        throw "route aborted";
      }
    }
    router.events.on("routeChangeStart", onRouteChange);
    return () => router.events.off("routeChangeStart", onRouteChange);
  }, [dirty, router]);
}

// ── Effect-location badge — shows admins where a setting takes effect ─────────
export type EffectScope = "全站" | "首页" | "结果页" | "SEO" | "社交分享" | "后台" | "顶部公告" | "登录与验证" | "邮件通知";
const EFFECT_COLORS: Record<EffectScope, string> = {
  "全站":   "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 border-blue-200/60 dark:border-blue-800/40",
  "首页":   "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200/60 dark:border-emerald-800/40",
  "结果页": "bg-purple-100 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400 border-purple-200/60 dark:border-purple-800/40",
  "SEO":    "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 border-orange-200/60 dark:border-orange-800/40",
  "社交分享":"bg-cyan-100 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-400 border-cyan-200/60 dark:border-cyan-800/40",
  "后台":   "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 border-red-200/60 dark:border-red-800/40",
  "顶部公告":"bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200/60 dark:border-amber-800/40",
  "登录与验证":"bg-fuchsia-100 dark:bg-fuchsia-950/40 text-fuchsia-700 dark:text-fuchsia-400 border-fuchsia-200/60 dark:border-fuchsia-800/40",
  "邮件通知":"bg-teal-100 dark:bg-teal-950/40 text-teal-700 dark:text-teal-400 border-teal-200/60 dark:border-teal-800/40",
};
export function EffectBadge({ scope }: { scope: EffectScope }) {
  return (
    <span className={cn(
      "inline-flex items-center px-1.5 py-0.5 rounded-md text-[9px] font-semibold border shrink-0 tracking-wide",
      EFFECT_COLORS[scope],
    )}>
      {scope}
    </span>
  );
}

export function SectionTitle({
  icon: Icon, title, desc, effect,
}: { icon: React.ElementType; title: string; desc?: string; effect?: EffectScope }) {
  return (
    <div className="flex items-start gap-3">
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

export function Field({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs font-semibold text-foreground">{label}</Label>
      {desc && <p className="text-[11px] text-muted-foreground -mt-0.5">{desc}</p>}
      {children}
    </div>
  );
}

export function Toggle({
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

export function PasswordField({ label, desc, value, onChange, placeholder }: {
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

export function TextareaField({ label, desc, value, onChange, rows = 3, placeholder }: {
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

export type RichItem = { text: string; color?: string; size?: "xs" | "sm" | "base"; bold?: boolean };
export function parseRichItems(raw: string): RichItem[] {
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

export function MultiItemInput({ value, onChange, placeholder }: {
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
            <div className="w-6 h-6 rounded-md border border-border/60 bg-muted/30 flex items-center justify-center text-[10px] font-bold text-muted-foreground shrink-0 tabular-nums select-none">
              {idx + 1}
            </div>
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
            {item.color && (
              <button
                type="button"
                onClick={() => update(idx, "color", undefined)}
                title="清除颜色"
                className="w-5 h-5 rounded border border-border/50 text-muted-foreground/60 hover:text-destructive hover:border-destructive/40 flex items-center justify-center text-xs transition-colors shrink-0"
              >×</button>
            )}
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
            <button
              type="button"
              onClick={() => update(idx, "bold", !item.bold)}
              title="粗体"
              className={`w-6 h-6 rounded-md border text-xs font-bold shrink-0 transition-colors ${item.bold ? "bg-foreground text-background border-foreground" : "border-border/60 text-muted-foreground hover:border-border"}`}
            >B</button>
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

export function SelectField({ label, desc, value, onChange, options }: {
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