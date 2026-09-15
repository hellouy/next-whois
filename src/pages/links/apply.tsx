import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSiteSettings } from "@/lib/site-settings";
import { useLocale } from "@/lib/locale-context";
import { cn } from "@/lib/utils";
import {
  RiArrowLeftSLine,
  RiLinksLine,
  RiLoader4Line,
  RiCheckboxCircleLine,
  RiTimeLine,
  RiFileCopyLine,
  RiCheckLine,
  RiExternalLinkLine,
} from "@remixicon/react";

interface BadgeData {
  textHtml: string;
  iconHtml: string;
  iconUrl: string;
  siteUrl: string;
  siteName: string;
}

interface Meta {
  siteLabel: string;
  siteUrl: string;
  categories: string[];
  badge: BadgeData;
}

interface Probe {
  url: string;
  status?: number;
  found: boolean;
  reason?: string;
  error?: string;
}

interface SubmitResult {
  ok: boolean;
  status: "approved" | "review";
  autoApproved: boolean;
  backlink: { found: boolean; pages: Probe[]; checkedAt: string };
  badge: { textHtml: string; iconHtml: string; siteUrl: string; siteName: string };
  siteLabel: string;
}

const fadeUp = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.3, ease: [0.32, 0.72, 0, 1] } },
};

const inputCls =
  "w-full rounded-xl border border-border bg-background/60 px-3.5 py-2.5 text-sm outline-none transition-colors focus:border-primary";

export default function LinksApplyPage() {
  const { locale } = useLocale();
  const settings = useSiteSettings();
  const siteName = settings.site_logo_text || "WHOIS";
  const zh = locale === "zh" || locale === "zh-tw";

  const [meta, setMeta] = React.useState<Meta | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [errorMsg, setErrorMsg] = React.useState("");
  const [result, setResult] = React.useState<SubmitResult | null>(null);
  const [copied, setCopied] = React.useState<"text" | "icon" | null>(null);

  const formRef = React.useRef<HTMLFormElement>(null);

  React.useEffect(() => {
    fetch("/api/links/apply")
      .then(r => r.json())
      .then(d => setMeta(d))
      .catch(() => {});
  }, []);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!formRef.current) return;
    const fd = new FormData(formRef.current);
    setErrorMsg("");
    setSubmitting(true);
    try {
      const res = await fetch("/api/links/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: fd.get("name"),
          url: fd.get("url"),
          description: fd.get("description"),
          category: fd.get("category"),
          email: fd.get("email"),
          _hp: fd.get("hp") || "",
          _t: Date.now(),
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setErrorMsg(data.error || (zh ? "提交失败，请稍后再试" : "Submit failed. Please try again."));
        return;
      }
      setResult(data);
    } catch {
      setErrorMsg(zh ? "网络错误，请稍后再试" : "Network error. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  async function copyHtml(which: "text" | "icon") {
    const badge = result?.badge ?? meta?.badge;
    if (!badge) return;
    const html = which === "text" ? badge.textHtml : badge.iconHtml;
    try {
      await navigator.clipboard.writeText(html);
      setCopied(which);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      setErrorMsg(zh ? "复制失败，请手动全选复制" : "Copy failed. Please select and copy manually.");
    }
  }

  const title = zh ? "申请友链" : "Apply for a link";
  const head = `${title} — ${siteName}`;

  return (
    <>
      <Head>
        <title key="title">{head}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="relative w-full max-w-3xl mx-auto px-4 sm:px-6 py-6 pb-16">
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-0 top-0 bottom-8 bg-dot-pattern text-muted-foreground/10 dark:text-muted-foreground/5"
          />

          <motion.div
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            className="relative flex items-center gap-3 mb-6"
          >
            <Link
              href="/links"
              aria-label={zh ? "返回" : "Back"}
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500 via-sky-500 to-violet-500 flex items-center justify-center text-white shadow-md shadow-emerald-500/20 rotate-[-6deg]">
                <RiLinksLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{title}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {zh
                    ? `本站 ${meta?.siteLabel || siteName} 的友链申请 · ${meta?.siteUrl || ""}`
                    : `Apply for a link on ${meta?.siteLabel || siteName}`}
                </p>
              </div>
            </div>
          </motion.div>

          {result ? (
            <motion.div initial="hidden" animate="visible" variants={fadeUp} className="relative space-y-4">
              {/* Status banner */}
              <div
                className={cn(
                  "rounded-xl p-4 flex items-start gap-3 border",
                  result.autoApproved
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    : "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
                )}
              >
                {result.autoApproved ? (
                  <RiCheckboxCircleLine className="w-5 h-5 mt-0.5 shrink-0" />
                ) : (
                  <RiTimeLine className="w-5 h-5 mt-0.5 shrink-0" />
                )}
                <div>
                  <p className="text-sm font-bold">
                    {result.autoApproved
                      ? zh ? "已自动通过并上链" : "Approved & published"
                      : zh ? "申请已收到，等待人工审核" : "Received, awaiting review"}
                  </p>
                  <p className="text-xs mt-1 opacity-80 leading-relaxed">
                    {result.autoApproved
                      ? zh
                        ? `已在你的站点检测到指向本站的链接，友链已自动上架。`
                        : "We found a link back to this site on yours — your link is now live."
                      : zh
                        ? "未在你的站点检测到本站链接，请在你的页脚添加下方徽章后等待管理员审核。"
                        : "We couldn't find a link back to us on your site. Add a badge below and await admin review."}
                  </p>
                </div>
              </div>

              {/* Badge cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {(
                  [
                    ["text", result.badge.textHtml],
                    ["icon", result.badge.iconHtml],
                  ] as const
                ).map(([which, html]) => (
                  <div
                    key={which}
                    className="glass-panel border border-border rounded-xl p-4 flex flex-col gap-3"
                  >
                    <p className="text-[11px] font-bold text-muted-foreground tracking-wide">
                      {which === "text" ? (zh ? "文字徽章" : "Text badge") : (zh ? "图标徽章" : "Icon badge")}
                    </p>
                    <div
                      className="min-h-10 rounded-lg bg-muted/40 border border-border px-3 py-2 flex items-center overflow-x-auto"
                      dangerouslySetInnerHTML={{ __html: html }}
                    />
                    <button
                      type="button"
                      onClick={() => copyHtml(which)}
                      className="inline-flex items-center justify-center gap-1.5 text-xs font-semibold text-primary bg-primary/10 hover:bg-primary/15 rounded-lg px-3 py-2 transition-colors"
                    >
                      {copied === which ? <RiCheckLine className="w-3.5 h-3.5" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                      {copied === which ? (zh ? "已复制" : "Copied") : (zh ? "复制 HTML" : "Copy HTML")}
                    </button>
                  </div>
                ))}
              </div>

              {/* Backlink probe summary */}
              <div className="glass-panel border border-border rounded-xl p-4">
                <p className="text-[11px] font-bold text-muted-foreground tracking-wide mb-2">
                  {zh ? "反链检测摘要" : "Backlink check summary"}
                </p>
                <p className="text-sm mb-2">
                  {result.autoApproved
                    ? zh ? "已在以下页面检测到本站链接：" : "We found a link on:"
                    : zh ? "已检查以下页面（未检测到本站链接）：" : "Checked (no link found):"}
                </p>
                <ul className="space-y-1">
                  {result.backlink.pages.map((p, i) => (
                    <li key={i} className="flex items-center gap-2 text-xs">
                      <span className={cn("w-1.5 h-1.5 rounded-full", p.found ? "bg-emerald-500" : "bg-muted-foreground/40")} />
                      <span className="font-mono text-muted-foreground truncate max-w-[80%]">{p.url}</span>
                      <span className="ml-auto shrink-0 text-muted-foreground/60">
                        {p.error ? (zh ? p.error === "timeout" ? "超时" : p.error : p.error) : p.status}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </motion.div>
          ) : (
            <div className="relative space-y-4">
              {/* Step 1 — copy badge before filling the form */}
              {meta?.badge ? (
                <motion.div initial="hidden" animate="visible" variants={fadeUp} className="glass-panel border border-border rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="w-5 h-5 rounded-full bg-foreground text-background flex items-center justify-center text-[11px] font-bold shrink-0">1</span>
                    <p className="text-sm font-bold">{zh ? "先复制本站徽章" : "Copy our badge first"}</p>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed mb-4">
                    {zh
                      ? "在你的站点页脚放置以下徽章或文字链接，提交后系统检测到会自动通过。"
                      : "Place one of the badges (or a text link) in your site's footer. We auto-approve when we detect it."}
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {(
                      [
                        ["text", meta.badge.textHtml],
                        ["icon", meta.badge.iconHtml],
                      ] as const
                    ).map(([which, html]) => (
                      <div key={which} className="border border-border rounded-xl p-3.5 flex flex-col gap-2.5">
                        <p className="text-[11px] font-bold text-muted-foreground tracking-wide">
                          {which === "text" ? (zh ? "文字徽章" : "Text badge") : (zh ? "图标徽章" : "Icon badge")}
                        </p>
                        <div
                          className="min-h-9 rounded-lg bg-muted/40 border border-border px-3 py-2 flex items-center overflow-x-auto"
                          dangerouslySetInnerHTML={{ __html: html }}
                        />
                        <button
                          type="button"
                          onClick={() => copyHtml(which)}
                          className="inline-flex items-center justify-center gap-1.5 text-xs font-semibold text-primary bg-primary/10 hover:bg-primary/15 rounded-lg px-3 py-2 transition-colors"
                        >
                          {copied === which ? <RiCheckLine className="w-3.5 h-3.5" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                          {copied === which ? (zh ? "已复制" : "Copied") : (zh ? "复制 HTML" : "Copy HTML")}
                        </button>
                      </div>
                    ))}
                  </div>
                </motion.div>
              ) : (
                <div className="rounded-xl border border-border p-4 flex items-center gap-2 text-xs text-muted-foreground">
                  <RiLoader4Line className="w-4 h-4 animate-spin shrink-0" />
                  {zh ? "正在加载徽章…" : "Loading badge…"}
                </div>
              )}

              {/* Step 2 — fill the form */}
              <motion.form
                ref={formRef}
                onSubmit={onSubmit}
                initial="hidden"
                animate="visible"
                variants={fadeUp}
                className="glass-panel border border-border rounded-xl p-5 space-y-4"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-5 h-5 rounded-full bg-foreground text-background flex items-center justify-center text-[11px] font-bold shrink-0">2</span>
                  <p className="text-sm font-bold">{zh ? "填写站点资料" : "Fill in your site details"}</p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <label className="space-y-1.5">
                  <span className="text-xs font-semibold">
                    {zh ? "站点名称" : "Site name"} <span className="text-red-400">*</span>
                  </span>
                  <input name="name" required maxLength={80} placeholder={zh ? "示例：某某的博客" : "My blog"} className={inputCls} />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs font-semibold">
                    {zh ? "网站地址" : "Website URL"} <span className="text-red-400">*</span>
                  </span>
                  <input name="url" required type="url" maxLength={253} placeholder="https://example.com" className={inputCls} />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs font-semibold">{zh ? "联系邮箱" : "Contact email"} <span className="text-red-400">*</span></span>
                  <input name="email" required type="email" maxLength={254} placeholder="you@example.com" className={inputCls} />
                </label>
                <label className="space-y-1.5">
                  <span className="text-xs font-semibold">
                    {zh ? "建议分类" : "Suggested category"}
                  </span>
                  {meta && meta.categories.length > 0 ? (
                    <select name="category" className={cn(inputCls, "appearance-none")}>
                      <option value="">{zh ? "不限" : "None"}</option>
                      {meta.categories.map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  ) : (
                    <input name="category" maxLength={40} placeholder={zh ? "博客 / 工具 / 社区" : "Blog / Tool / Community"} className={inputCls} />
                  )}
                </label>
              </div>
              <label className="space-y-1.5 block">
                <span className="text-xs font-semibold">{zh ? "站点简介" : "Description"}</span>
                <textarea
                  name="description"
                  maxLength={500}
                  rows={3}
                  placeholder={zh ? "用一两句话介绍你的站点…" : "Introduce your site in a sentence or two…"}
                  className={cn(inputCls, "resize-none")}
                />
              </label>

              {/* Honeypot — visually hidden, bots fill it */}
              <input
                name="hp"
                type="text"
                tabIndex={-1}
                autoComplete="off"
                aria-hidden
                className="absolute -left-[9999px] w-px h-px opacity-0"
              />

              {errorMsg && (
                <p className="text-xs text-red-500 font-medium">{errorMsg}</p>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full inline-flex items-center justify-center gap-2 text-sm font-semibold text-primary bg-primary/10 hover:bg-primary/15 disabled:opacity-50 rounded-xl px-4 py-3 transition-colors"
              >
                {submitting && <RiLoader4Line className="w-4 h-4 animate-spin" />}
                {submitting
                  ? zh ? "正在检测对方站点…" : "Checking your site…"
                  : zh ? "提交申请" : "Submit application"}
              </button>

              <p className="text-[11px] text-muted-foreground/70 leading-relaxed">
                {zh
                  ? "提交后系统会自动抓取你的页面检索本站链接：若页脚已放置本站链接将自动通过；否则进入人工审核。请先在你的页面添加上方可复制的徽章。"
                  : "After submitting, we automatically scan your pages for a link back to us: found → auto-approved, otherwise → manual review. Add one of the badges above first to speed things up."}
              </p>
              </motion.form>
            </div>
          )}
        </main>
      </ScrollArea>
    </>
  );
}