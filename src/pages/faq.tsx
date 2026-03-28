import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine,
  RiQuestionLine,
  RiSearchLine,
  RiGlobalLine,
  RiShieldCheckLine,
  RiCodeSSlashLine,
  RiTimeLine,
  RiLockLine,
  RiServerLine,
  RiInformationLine,
  RiArrowRightSLine,
} from "@remixicon/react";

const card = {
  hidden: { opacity: 0, y: 10 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.05, duration: 0.3 },
  }),
};

type FaqItem = {
  icon: React.ElementType;
  color: string;
  q: string;
  qEn: string;
  a: string;
  aEn: string;
};

const FAQS: FaqItem[] = [
  {
    icon: RiSearchLine,
    color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
    q: "这个工具可以查询什么？",
    qEn: "What can this tool look up?",
    a: "支持多种查询类型：域名（含国际化域名 IDN）、IPv4/IPv6 地址、ASN（自治系统号）、CIDR 网段。域名查询会同时获取 WHOIS 和 RDAP 数据；IP 查询返回地理位置、ISP、代理检测等信息；ASN 查询显示网络运营商及路由信息。",
    aEn: "Multiple query types are supported: domain names (including internationalized IDN domains), IPv4/IPv6 addresses, ASN (Autonomous System Numbers), and CIDR ranges. Domain queries retrieve both WHOIS and RDAP data; IP queries return geolocation, ISP, proxy detection, and more; ASN queries show network operator and routing information.",
  },
  {
    icon: RiGlobalLine,
    color: "bg-purple-100 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400",
    q: "WHOIS 和 RDAP 有什么区别？",
    qEn: "What is the difference between WHOIS and RDAP?",
    a: "WHOIS 是一种较旧的纯文本协议，不同注册商的格式各异，部分字段可能缺失。RDAP（注册数据访问协议）是现代化的 JSON 格式替代方案，结构统一、易于解析，并支持认证和更丰富的数据字段。本工具优先使用 RDAP，在 RDAP 不可用时自动回退到 WHOIS。",
    aEn: "WHOIS is an older plain-text protocol with inconsistent formatting across registrars and potential missing fields. RDAP (Registration Data Access Protocol) is the modern JSON-based replacement with unified structure, easier parsing, and richer data fields including authentication support. This tool prioritizes RDAP and automatically falls back to WHOIS when RDAP is unavailable.",
  },
  {
    icon: RiTimeLine,
    color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
    q: "查询数据是实时的吗？",
    qEn: "Is the query data real-time?",
    a: "域名 WHOIS/RDAP 查询结果会短暂缓存（通常 1 小时），以提高响应速度并减少对注册管理机构服务器的负载。如需强制刷新，可在查询结果页中重新提交查询。DNS 查询、SSL 证书检查、HTTP 检测均为实时数据，不缓存。",
    aEn: "Domain WHOIS/RDAP results are briefly cached (typically 1 hour) to improve response speed and reduce load on registry servers. To force a refresh, simply resubmit the query on the results page. DNS queries, SSL certificate checks, and HTTP checks are real-time and not cached.",
  },
  {
    icon: RiLockLine,
    color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
    q: "我的查询记录会被保存吗？",
    qEn: "Are my search queries stored?",
    a: "本工具不会永久存储您的查询内容。临时缓存（Redis）仅用于提高响应性能，会自动过期清除。速率限制功能会使用您的 IP 地址进行计数，但不会记录具体的查询内容。详情请参阅隐私政策。",
    aEn: "This tool does not permanently store your search queries. Temporary cache (Redis) is used only to improve response performance and expires automatically. Rate limiting uses your IP address for counting but does not log specific query content. See our Privacy Policy for more details.",
  },
  {
    icon: RiShieldCheckLine,
    color: "bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400",
    q: "为什么注册人信息显示为 REDACTED？",
    qEn: "Why does registrant information show as REDACTED?",
    a: "根据 GDPR 及各国隐私保护法规，大多数通用顶级域名（如 .com/.net）的注册人个人信息已被隐藏保护。部分国家和地区的顶级域名（ccTLD）仍可能显示完整信息。这不是工具的限制，而是注册管理机构的数据保护政策。",
    aEn: "In compliance with GDPR and various national privacy protection laws, registrant personal information for most generic TLDs (such as .com/.net) is redacted. Some country-code TLDs (ccTLDs) may still display full information. This is not a tool limitation but a data protection policy enforced by the registries.",
  },
  {
    icon: RiServerLine,
    color: "bg-cyan-100 dark:bg-cyan-950/40 text-cyan-600 dark:text-cyan-400",
    q: "工具箱里有哪些功能？",
    qEn: "What features are available in the toolbox?",
    a: "工具箱包含：DNS 记录查询（支持 A/AAAA/MX/NS/CNAME/TXT/SOA/CAA，含 SPF/DMARC/DKIM 分析）、SSL 证书检查（证书详情、有效期、证书链）、IP 地理位置与 ASN 查询、HTTP 状态检测（重定向链路、响应时间）、ICP 备案查询（中国网站备案信息），以及 136+ 款精选外部域名工具导航。",
    aEn: "The toolbox includes: DNS record lookup (A/AAAA/MX/NS/CNAME/TXT/SOA/CAA with SPF/DMARC/DKIM analysis), SSL certificate check (details, expiry, certificate chain), IP geolocation & ASN lookup, HTTP status check (redirect chain, response time), ICP filing lookup (China website registration), and a curated directory of 136+ external domain tools.",
  },
  {
    icon: RiCodeSSlashLine,
    color: "bg-indigo-100 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400",
    q: "如何使用 API 接口？",
    qEn: "How do I use the API?",
    a: "本工具提供 WHOIS/RDAP 查询 API。当管理员启用 API Key 功能后，需在请求头中携带 X-API-Key 才能访问。具体的 API 文档、参数说明和示例请参见文档页面。DNS、SSL、IP 等工具型 API 仅供平台内部调用，不作为公开 API 提供。",
    aEn: "This tool provides a WHOIS/RDAP lookup API. When the administrator enables API Key authentication, you need to include an X-API-Key header in your requests. For detailed API documentation, parameters, and examples, see the Docs page. DNS, SSL, IP and other utility APIs are for internal platform use only and are not available as public APIs.",
  },
  {
    icon: RiInformationLine,
    color: "bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400",
    q: "域名价格数据准确吗？",
    qEn: "How accurate is the domain pricing data?",
    a: "域名注册价格数据来源于 nazhumi.com 和 miqingju.com 等第三方数据平台，价格以各注册商原始币种显示。数据可能存在延迟或差异，实际价格以注册商官网为准。溢价域名的实际注册价格可能远高于参考价格，请直接向注册商确认。",
    aEn: "Domain registration pricing data is sourced from third-party platforms such as nazhumi.com and miqingju.com, displayed in each registrar's original currency. Data may have delays or discrepancies — always verify the final price on the registrar's official website. Premium domain registration prices may be significantly higher than the reference prices shown.",
  },
];

export default function FaqPage() {
  const settings = useSiteSettings();
  const { locale, t } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || settings.site_title || "X.RW";
  const pageTitle = t("nav_faq");

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
        <meta
          name="description"
          content={
            isChinese
              ? `${siteName} 常见问题解答 — WHOIS、RDAP、DNS 查询、域名工具使用指南`
              : `${siteName} Frequently Asked Questions — WHOIS, RDAP, DNS lookup and domain tools guide`
          }
        />
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
                <RiQuestionLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {isChinese ? "使用帮助 · 功能说明 · 常见疑问" : "Usage guide · Feature overview · Common questions"}
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            {FAQS.map((item, i) => (
              <motion.div
                key={item.q}
                custom={i}
                initial="hidden"
                animate="visible"
                variants={card}
                className="glass-panel border border-border rounded-xl overflow-hidden"
              >
                <div className="p-5">
                  <div className="flex items-start gap-3 mb-3">
                    <div className={`p-2 rounded-lg shrink-0 mt-0.5 ${item.color}`}>
                      <item.icon className="w-4 h-4" />
                    </div>
                    <h2 className="text-sm font-semibold leading-snug pt-1.5">
                      {isChinese ? item.q : item.qEn}
                    </h2>
                  </div>
                  <p className="text-[13px] text-muted-foreground leading-relaxed pl-11">
                    {isChinese ? item.a : item.aEn}
                  </p>
                </div>
              </motion.div>
            ))}

            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: FAQS.length * 0.05 + 0.1, duration: 0.3 }}
              className="glass-panel border border-border rounded-xl p-5"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-muted/60 text-muted-foreground shrink-0">
                  <RiGlobalLine className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold leading-none mb-1">
                    {isChinese ? "还有其他问题？" : "Have more questions?"}
                  </p>
                  <p className="text-[12px] text-muted-foreground">
                    {isChinese
                      ? "查看 API 文档了解更多技术细节，或联系我们获取支持。"
                      : "Check the API docs for technical details, or contact us for support."}
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Link
                    href="/docs"
                    className="inline-flex items-center gap-1 text-[11px] font-medium px-3 py-1.5 rounded-lg bg-muted/60 hover:bg-muted border border-border transition-colors text-muted-foreground hover:text-foreground"
                  >
                    {isChinese ? "文档" : "Docs"}
                    <RiArrowRightSLine className="w-3.5 h-3.5" />
                  </Link>
                  <Link
                    href="/about"
                    className="inline-flex items-center gap-1 text-[11px] font-medium px-3 py-1.5 rounded-lg bg-muted/60 hover:bg-muted border border-border transition-colors text-muted-foreground hover:text-foreground"
                  >
                    {isChinese ? "关于" : "About"}
                    <RiArrowRightSLine className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            </motion.div>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
