import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import { VERSION } from "@/lib/env";
import {
  RiArrowLeftSLine,
  RiArrowRightSLine,
  RiInformationLine,
  RiHistoryLine,
  RiGlobalLine,
  RiLinksLine,
  RiShieldCheckLine,
  RiCodeSSlashLine,
  RiSearchLine,
  RiTimeLine,
  RiTranslate2,
  RiSmartphoneLine,
  RiGithubLine,
  RiMailLine,
  RiStarLine,
  RiServerLine,
  RiDatabaseLine,
  RiBrainLine,
  RiHeartLine,
  RiExternalLinkLine,
  RiUserLine,
  RiQuestionAnswerLine,
  RiFileTextLine,
} from "@remixicon/react";

function FaviconImage({ url, name }: { url: string; name: string }) {
  const [failed, setFailed] = React.useState(false);
  const hostname = React.useMemo(() => {
    try { return new URL(url).hostname; } catch { return name; }
  }, [url, name]);
  if (failed) return <RiHeartLine className="w-4 h-4 text-rose-400" />;
  return (
    <img
      src={`https://www.google.com/s2/favicons?domain=${hostname}&sz=64`}
      alt={name}
      width={18}
      height={18}
      className="rounded-sm"
      onError={() => setFailed(true)}
    />
  );
}

const FEATURES = [
  {
    icon: RiSearchLine,
    color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
    title: "多类型查询",
    titleEn: "Multi-type Lookup",
    desc: "支持域名、IPv4/IPv6、ASN、CIDR 网段，一站式查询",
    descEn: "Domain, IPv4/v6, ASN and CIDR lookups all in one place",
  },
  {
    icon: RiGlobalLine,
    color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
    title: "WHOIS + RDAP 双协议",
    titleEn: "WHOIS + RDAP Dual Protocol",
    desc: "优先使用 RDAP，回退 WHOIS，确保最佳数据质量",
    descEn: "RDAP-first with WHOIS fallback for the best data quality",
  },
  {
    icon: RiTimeLine,
    color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
    title: "到期提醒",
    titleEn: "Expiry Reminders",
    desc: "订阅域名，到期前 90/30/7/1 天自动发送邮件提醒",
    descEn: "Subscribe to domains and receive email alerts 90/30/7/1 days before expiry",
  },
  {
    icon: RiTranslate2,
    color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
    title: "8 种语言",
    titleEn: "8 Languages",
    desc: "支持中文简繁、English、日本語、한국어、Deutsch、français、русский",
    descEn: "Chinese, English, Japanese, Korean, German, French, Russian & more",
  },
  {
    icon: RiSmartphoneLine,
    color: "bg-pink-100 dark:bg-pink-950/40 text-pink-600 dark:text-pink-400",
    title: "移动端友好",
    titleEn: "Mobile Friendly",
    desc: "针对 iOS / Android 优化，支持 PWA 安装到桌面",
    descEn: "Optimized for iOS/Android with PWA support for home screen installation",
  },
  {
    icon: RiShieldCheckLine,
    color: "bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400",
    title: "品牌认领",
    titleEn: "Brand Stamp",
    desc: "注册后可认领你的域名品牌标签，展示在查询结果页",
    descEn: "Register to claim brand stamps displayed on lookup result pages",
  },
];

const TECH_STACK = [
  { icon: RiCodeSSlashLine, name: "Next.js 14", desc: "Pages Router · App 框架", descEn: "Pages Router · App Framework" },
  { icon: RiServerLine, name: "RDAP + WHOIS", desc: "双协议域名查询", descEn: "Dual Protocol Domain Lookup" },
  { icon: RiDatabaseLine, name: "PostgreSQL", desc: "Supabase 托管数据库", descEn: "Supabase Hosted Database" },
  { icon: RiBrainLine, name: "Tailwind + Shadcn", desc: "UI 组件系统", descEn: "UI Component System" },
];

const SUB_PAGES = [
  {
    href: "/changelog",
    settingKey: "enable_changelog",
    icon: RiHistoryLine,
    color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
    title: "更新记录",
    titleEn: "Changelog",
    desc: "查看各版本新增功能与修复记录",
    descEn: "View features and fixes in each release",
  },
  {
    href: "/tlds",
    settingKey: "",
    icon: RiGlobalLine,
    color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
    title: "支持后缀",
    titleEn: "Supported TLDs",
    desc: "浏览本站支持 WHOIS/RDAP 查询的所有后缀",
    descEn: "Browse all TLDs supported for WHOIS/RDAP lookup",
  },
  {
    href: "/links",
    settingKey: "enable_links",
    icon: RiLinksLine,
    color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
    title: "友情链接",
    titleEn: "Friendly Links",
    desc: "站长精选推荐 · 朋友们的网站",
    descEn: "Curated recommendations and friends' websites",
  },
  {
    href: "/docs",
    settingKey: "enable_docs",
    icon: RiCodeSSlashLine,
    color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
    title: "API 文档",
    titleEn: "API Docs",
    desc: "接入我们的查询 API，构建你自己的应用",
    descEn: "Integrate our lookup API to build your own applications",
  },
  {
    href: "/faq",
    settingKey: "",
    icon: RiQuestionAnswerLine,
    color: "bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400",
    title: "帮助中心",
    titleEn: "FAQ",
    desc: "常见问题解答，了解平台使用方法",
    descEn: "Frequently asked questions about using this platform",
  },
  {
    href: "/privacy",
    settingKey: "",
    icon: RiShieldCheckLine,
    color: "bg-slate-100 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400",
    title: "隐私政策",
    titleEn: "Privacy Policy",
    desc: "了解我们如何收集和处理您的数据",
    descEn: "How we collect and handle your data",
  },
  {
    href: "/terms",
    settingKey: "",
    icon: RiFileTextLine,
    color: "bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400",
    title: "服务条款",
    titleEn: "Terms of Service",
    desc: "使用本平台须遵守的相关条款与规定",
    descEn: "Terms and conditions for using this platform",
  },
];

const DEFAULT_THANKS = [
  { name: "nazhumi.com", url: "https://www.nazhumi.com", desc: "低注册价格支持", descEn: "Low registration price support" },
  { name: "tian.hu", url: "https://tian.hu", desc: "域名翻译数据支持", descEn: "Domain translation data support" },
  { name: "miqingju.com", url: "https://www.miqingju.com", desc: "域名比价查询支持", descEn: "Domain price comparison support" },
  { name: "yisi.yun", url: "https://yisi.yun", desc: "API 数据服务支持", descEn: "API data service" },
];

const card = {
  hidden: { opacity: 0, y: 12 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, delay: i * 0.06, ease: [0.32, 0.72, 0, 1] },
  }),
};

export default function AboutPage() {
  const { locale } = useTranslation();
  const settings = useSiteSettings();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || "WHOIS";
  const pageTitle = settings.about_title || (isChinese ? "关于我们" : "About");

  const introZh = settings.about_content || `${siteName} 是一款面向域名投资者、技术人员与网站运营者的专业查询工具，支持域名 WHOIS/RDAP、IP 地址、ASN 自治系统、CIDR 网段、DNS 记录及 SSL 证书查询。提供到期提醒、品牌认领、域名工具箱等增值功能，助力你高效管理与评估域名资产。`;
  const introEn = settings.about_intro_en || `${siteName} is a professional lookup tool for domain investors, developers, and site operators. It supports WHOIS/RDAP, IP address, ASN, CIDR, DNS records, and SSL certificate lookups, with value-added features like expiry reminders, brand stamps, and a domain toolbox.`;

  const githubUrl = settings.about_github_url || "https://github.com/zmh-program/next-whois";
  const authorName = settings.about_author_name || "zmh-program";
  const authorUrl = settings.about_author_url || "https://zmh.me";
  let thanksItems = DEFAULT_THANKS;
  if (settings.about_thanks?.trim()) {
    try {
      const parsed = JSON.parse(settings.about_thanks);
      if (Array.isArray(parsed)) {
        thanksItems = parsed.map((t: { name: string; url: string; desc?: string; descEn?: string }) => ({
          name: t.name || "",
          url: t.url || "",
          desc: t.desc || "",
          descEn: t.descEn || t.desc || "",
        }));
      }
    } catch {
      thanksItems = DEFAULT_THANKS;
    }
  }

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6 pb-16">
          <div className="flex items-center gap-3 mb-6">
            <Link
              href="/"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
                <RiInformationLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {isChinese ? "项目介绍 · 功能说明 · 技术栈" : "Project info · Features · Tech stack"}
                </p>
              </div>
            </div>
            <Badge variant="outline" className="ml-auto font-mono text-[10px]">
              v{VERSION}
            </Badge>
          </div>

          <div className="space-y-6">
            {/* Intro */}
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35 }}
              className="glass-panel border border-border rounded-xl p-6 relative overflow-hidden"
            >
              <div className="absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-primary/5 to-transparent pointer-events-none" />
              <div className="relative z-10">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-12 h-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center">
                    <RiSearchLine className="w-6 h-6 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold tracking-tight">{siteName}</h2>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {isChinese ? "专业域名信息查询工具" : "Professional domain information lookup tool"}
                    </p>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {isChinese ? introZh : introEn}
                </p>
                <Link
                  href="/feedback"
                  className="inline-flex items-center gap-1.5 text-[11px] font-medium mt-3 px-3 py-1.5 rounded-lg bg-muted/60 hover:bg-muted border border-border transition-colors text-muted-foreground hover:text-foreground"
                >
                  <RiMailLine className="w-3.5 h-3.5" />
                  {isChinese ? "联系 / 反馈" : "Contact / Feedback"}
                </Link>
              </div>
            </motion.div>

            {/* Features */}
            <div>
              <h3 className="text-sm font-semibold text-muted-foreground mb-3 px-1">
                {isChinese ? "核心功能" : "Core Features"}
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {FEATURES.map((f, i) => (
                  <motion.div
                    key={f.title}
                    custom={i}
                    initial="hidden"
                    animate="visible"
                    variants={card}
                    className="glass-panel border border-border rounded-xl p-4 flex items-start gap-3"
                  >
                    <div className={`p-2 rounded-lg shrink-0 ${f.color}`}>
                      <f.icon className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold leading-none mb-1">
                        {isChinese ? f.title : f.titleEn}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug">
                        {isChinese ? f.desc : f.descEn}
                      </p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* More pages */}
            <div>
              <h3 className="text-sm font-semibold text-muted-foreground mb-3 px-1">
                {isChinese ? "更多页面" : "More Pages"}
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {SUB_PAGES.filter(p => !p.settingKey || !!(settings as unknown as Record<string, string>)[p.settingKey]).map((p, i) => (
                  <motion.div key={p.href} custom={i + 6} initial="hidden" animate="visible" variants={card}>
                    <Link
                      href={p.href}
                      className="glass-panel border border-border rounded-xl p-4 flex items-center gap-3 hover:border-primary/40 hover:bg-muted/40 transition-all group block"
                    >
                      <div className={`p-2 rounded-lg shrink-0 ${p.color}`}>
                        <p.icon className="w-4 h-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-semibold leading-none mb-1">
                          {isChinese ? p.title : p.titleEn}
                        </p>
                        <p className="text-[11px] text-muted-foreground leading-snug">
                          {isChinese ? p.desc : p.descEn}
                        </p>
                      </div>
                      <RiArrowRightSLine className="w-4 h-4 text-muted-foreground/40 group-hover:text-primary/60 transition-colors shrink-0" />
                    </Link>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Tech stack */}
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: 0.5 }}
              className="glass-panel border border-border rounded-xl p-5"
            >
              <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                <RiCodeSSlashLine className="w-4 h-4 text-muted-foreground" />
                {isChinese ? "技术栈" : "Tech Stack"}
              </h3>
              <div className="grid grid-cols-2 gap-3">
                {TECH_STACK.map((ts) => (
                  <div key={ts.name} className="flex items-center gap-2.5">
                    <div className="p-1.5 rounded-lg bg-muted/60 shrink-0">
                      <ts.icon className="w-3.5 h-3.5 text-muted-foreground" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold leading-none">{ts.name}</p>
                      <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{isChinese ? ts.desc : ts.descEn}</p>
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>

            {/* Based on Next Whois — author acknowledgment */}
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: 0.6 }}
              className="glass-panel border border-border rounded-xl p-5 flex items-start gap-4"
            >
              <div className="p-2.5 rounded-xl bg-muted/60 shrink-0">
                <RiStarLine className="w-5 h-5 text-muted-foreground" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold mb-1">
                  {isChinese ? "本站基于 · Next Whois 二次创作" : "Based on · Next Whois"}
                </p>
                <p className="text-[11px] text-muted-foreground leading-relaxed mb-3">
                  {isChinese
                    ? "感谢原作者的开源贡献，本站在 Next Whois 基础上进行二次开发，遵循 MIT 协议。"
                    : "Thanks to the original author's open source contribution. This site is built upon Next Whois under the MIT license."}
                </p>
                <div className="flex flex-wrap gap-2">
                  <a
                    href={githubUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-[11px] font-medium px-3 py-1.5 rounded-lg bg-muted/60 hover:bg-muted border border-border transition-colors"
                  >
                    <RiGithubLine className="w-3.5 h-3.5" />
                    GitHub
                  </a>
                  <a
                    href={authorUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-[11px] font-medium px-3 py-1.5 rounded-lg bg-muted/60 hover:bg-muted border border-border transition-colors"
                  >
                    <RiUserLine className="w-3.5 h-3.5" />
                    {authorName}
                  </a>
                </div>
              </div>
            </motion.div>

            {/* Thanks */}
            {thanksItems.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, delay: 0.7 }}
                className="glass-panel border border-border rounded-xl p-5"
              >
                <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                  <RiHeartLine className="w-4 h-4 text-rose-500" />
                  {isChinese ? "致谢" : "Acknowledgements"}
                </h3>
                <div className="grid grid-cols-2 gap-2.5">
                  {thanksItems.map((t) => (
                    <a
                      key={t.name}
                      href={t.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2.5 p-2.5 rounded-lg bg-muted/40 hover:bg-muted/70 border border-border/60 hover:border-border transition-all group"
                    >
                      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 bg-muted/60 overflow-hidden border border-border/40">
                        <FaviconImage url={t.url} name={t.name} />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-semibold leading-none truncate">{t.name}</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5 leading-snug truncate">
                          {isChinese ? t.desc : t.descEn}
                        </p>
                      </div>
                      <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/30 group-hover:text-muted-foreground/60 transition-colors shrink-0" />
                    </a>
                  ))}
                </div>
              </motion.div>
            )}
          </div>

        </main>
      </ScrollArea>
    </>
  );
}
