import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine,
  RiFileTextLine,
  RiGlobalLine,
  RiCodeSSlashLine,
  RiAlertLine,
  RiUserForbidLine,
  RiScalesLine,
  RiEditLine,
  RiMailLine,
  RiShieldLine,
} from "@remixicon/react";

const card = {
  hidden: { opacity: 0, y: 10 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.06, duration: 0.3 },
  }),
};

function Paragraph({ children }: { children: React.ReactNode }) {
  return <p className="text-[13px] text-muted-foreground leading-relaxed">{children}</p>;
}

function BulletList({ items }: { items: string[] }) {
  return (
    <ul className="mt-2 space-y-1.5">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-2 text-[13px] text-muted-foreground leading-relaxed">
          <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/40 mt-[5px] shrink-0" />
          {item}
        </li>
      ))}
    </ul>
  );
}

export default function TermsPage() {
  const settings = useSiteSettings();
  const { locale } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || settings.site_title || "X.RW";
  const pageTitle = isChinese ? "服务条款" : "Terms of Service";
  const contactEmail = settings.about_contact_email || settings.admin_email || "";

  type Section = {
    icon: React.ElementType;
    color: string;
    title: string;
    titleEn: string;
    content: React.ReactNode;
    contentEn: React.ReactNode;
  };

  const sections: Section[] = [
    {
      icon: RiGlobalLine,
      color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
      title: "服务说明",
      titleEn: "Service Description",
      content: (
        <div className="space-y-3">
          <Paragraph>
            {siteName} 是一款基于 Web 的域名信息查询工具，提供以下服务：
          </Paragraph>
          <BulletList items={[
            "WHOIS 和 RDAP 域名注册信息查询",
            "IPv4/IPv6 地址地理位置与 ASN 查询",
            "DNS 记录查询（含 SPF/DMARC/DKIM 分析）",
            "SSL/TLS 证书详情检查",
            "HTTP 状态与重定向链检测",
            "ICP 备案信息查询（中国网站）",
            "外部域名工具导航目录",
            "WHOIS/RDAP 查询 API 接口（需要 API Key）",
          ]} />
          <Paragraph>
            本服务通过互联网公开访问。查询结果来源于各域名注册管理机构、公开 DNS 服务器及第三方数据提供商，{siteName} 对这些数据来源的准确性不作保证。
          </Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            {siteName} is a web-based domain information lookup tool providing the following services:
          </Paragraph>
          <BulletList items={[
            "WHOIS and RDAP domain registration information lookup",
            "IPv4/IPv6 address geolocation and ASN lookup",
            "DNS record query (including SPF/DMARC/DKIM analysis)",
            "SSL/TLS certificate details check",
            "HTTP status and redirect chain detection",
            "ICP filing information lookup (China websites)",
            "External domain tools directory",
            "WHOIS/RDAP query API (requires API Key)",
          ]} />
          <Paragraph>
            The service is publicly accessible via the internet. Query results are sourced from domain registries, public DNS servers, and third-party data providers. {siteName} makes no guarantee regarding the accuracy of these data sources.
          </Paragraph>
        </div>
      ),
    },
    {
      icon: RiUserForbidLine,
      color: "bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400",
      title: "可接受使用政策",
      titleEn: "Acceptable Use Policy",
      content: (
        <div className="space-y-3">
          <Paragraph>使用本服务，您同意不得进行以下行为：</Paragraph>
          <BulletList items={[
            "以自动化方式大量抓取查询结果（超出正常使用范围的爬取行为）。",
            "尝试绕过速率限制，或通过代理/VPN 规避访问限制。",
            "将本服务用于任何违反法律法规的活动，包括但不限于域名抢注、网络钓鱼等。",
            "对服务平台发起任何形式的攻击，包括 DDoS、SQL 注入、XSS 等。",
            "利用本服务收集的信息骚扰、欺诈或伤害他人。",
            "冒充他人或虚假陈述您与任何个人或实体的关系。",
          ]} />
          <Paragraph>
            违反上述规定的行为可能导致账户封禁和 IP 访问限制，情节严重的将依法追究法律责任。
          </Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>By using this service, you agree not to:</Paragraph>
          <BulletList items={[
            "Scrape query results in bulk using automation (beyond normal use patterns).",
            "Attempt to bypass rate limits or circumvent access restrictions using proxies/VPNs.",
            "Use this service for any illegal activities, including but not limited to domain squatting or phishing.",
            "Launch any form of attack against the service platform, including DDoS, SQL injection, or XSS.",
            "Use information collected through this service to harass, defraud, or harm others.",
            "Impersonate any person or falsely represent your relationship with any individual or entity.",
          ]} />
          <Paragraph>
            Violations may result in account suspension and IP-level access restrictions. Serious violations may be subject to legal action.
          </Paragraph>
        </div>
      ),
    },
    {
      icon: RiCodeSSlashLine,
      color: "bg-purple-100 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400",
      title: "API 使用条款",
      titleEn: "API Usage Terms",
      content: (
        <div className="space-y-3">
          <Paragraph>
            使用 WHOIS/RDAP 查询 API 接口，需遵守以下附加条款：
          </Paragraph>
          <BulletList items={[
            "API Key 由管理员分配，不得共享给未经授权的第三方。",
            "API 调用受速率限制约束，超出限额的请求将被拒绝（429 Too Many Requests）。",
            "禁止将 API 用于商业转售目的（即不得将本服务的查询结果作为商品对外销售）。",
            "API 的可用性不提供 SLA 保证，服务可能因维护或不可抗力中断。",
            "我们保留随时修改 API 参数、返回格式或停止 API 服务的权利，并在合理范围内提前通知。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            The following additional terms apply to using the WHOIS/RDAP query API:
          </Paragraph>
          <BulletList items={[
            "API Keys are assigned by the administrator and must not be shared with unauthorized third parties.",
            "API calls are subject to rate limits; requests exceeding the quota will be rejected (429 Too Many Requests).",
            "Using the API for commercial resale is prohibited (i.e. you may not sell query results from this service as a product).",
            "No SLA is provided for API availability; the service may be interrupted for maintenance or force majeure.",
            "We reserve the right to modify API parameters, response formats, or discontinue the API service at any time, with reasonable advance notice.",
          ]} />
        </div>
      ),
    },
    {
      icon: RiAlertLine,
      color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
      title: "免责声明",
      titleEn: "Disclaimer",
      content: (
        <div className="space-y-3">
          <Paragraph>
            本服务按"现状"提供，不附带任何明示或暗示的保证。具体包括：
          </Paragraph>
          <BulletList items={[
            "数据准确性：WHOIS/RDAP 数据直接来源于注册管理机构，可能存在延迟、不完整或不准确的情况。域名注册价格数据来自第三方，仅供参考，实际价格以注册商官网为准。",
            "服务可用性：我们努力保持服务稳定，但不对服务的持续可用性作出任何承诺，定期维护或突发情况可能导致服务中断。",
            "查询结果的完整性：由于 GDPR 等隐私法规，部分域名的注册人信息可能被隐藏，这属于正常情况。",
            "外部链接：工具导航页面中的外部链接指向独立的第三方网站，我们对这些网站的内容不承担任何责任。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            This service is provided "as is" without any express or implied warranties. Specifically:
          </Paragraph>
          <BulletList items={[
            "Data accuracy: WHOIS/RDAP data is sourced directly from registries and may be delayed, incomplete, or inaccurate. Domain pricing data comes from third parties and is for reference only — always verify on the registrar's official website.",
            "Service availability: We strive to maintain service stability but make no commitment to continuous availability; scheduled maintenance or unexpected events may cause interruptions.",
            "Query result completeness: Due to privacy regulations such as GDPR, registrant information for some domains may be redacted — this is normal.",
            "External links: Links in the tools directory point to independent third-party websites for which we bear no responsibility.",
          ]} />
        </div>
      ),
    },
    {
      icon: RiScalesLine,
      color: "bg-indigo-100 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400",
      title: "责任限制",
      titleEn: "Limitation of Liability",
      content: (
        <div className="space-y-3">
          <Paragraph>
            在适用法律允许的最大范围内，{siteName} 及其运营者不对因使用或无法使用本服务而产生的任何直接、间接、附带、特殊或后果性损失承担责任，包括但不限于：
          </Paragraph>
          <BulletList items={[
            "基于查询结果作出商业决策（如域名注册、投资）所产生的损失。",
            "因服务中断导致的业务损失。",
            "数据传输过程中的安全问题（尽管我们采取了合理的安全措施）。",
            "第三方服务（注册管理机构、DNS 提供商等）的错误或中断。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            To the maximum extent permitted by applicable law, {siteName} and its operators shall not be liable for any direct, indirect, incidental, special, or consequential damages arising from use of or inability to use this service, including but not limited to:
          </Paragraph>
          <BulletList items={[
            "Losses from business decisions made based on query results (e.g. domain registration, investment).",
            "Business losses due to service interruptions.",
            "Security issues during data transmission (despite our reasonable security measures).",
            "Errors or interruptions from third-party services (registries, DNS providers, etc.).",
          ]} />
        </div>
      ),
    },
    {
      icon: RiShieldLine,
      color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
      title: "知识产权",
      titleEn: "Intellectual Property",
      content: (
        <div className="space-y-3">
          <Paragraph>
            本平台的代码基于开源项目构建。WHOIS/RDAP 查询结果属于各注册管理机构的公开数据。平台自身的设计、界面和功能实现受版权保护。
          </Paragraph>
          <Paragraph>
            您可以自由浏览查询结果供个人研究使用。未经许可，不得系统性地抓取、复制或商业利用本平台的内容和数据。
          </Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            This platform is built on open-source projects. WHOIS/RDAP query results are public data from domain registries. The platform's design, interface, and functional implementation are protected by copyright.
          </Paragraph>
          <Paragraph>
            You are free to view query results for personal research purposes. Systematic scraping, copying, or commercial exploitation of platform content and data is prohibited without permission.
          </Paragraph>
        </div>
      ),
    },
    {
      icon: RiEditLine,
      color: "bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400",
      title: "条款变更",
      titleEn: "Changes to Terms",
      content: (
        <div className="space-y-3">
          <Paragraph>
            我们保留随时修改本服务条款的权利。重大变更将在平台上以公告形式提前告知。继续使用本服务即表示您接受更新后的条款。
          </Paragraph>
          <Paragraph>
            建议您定期查阅本页面以了解最新条款。本条款的最新版本将始终发布于本页面。
          </Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            We reserve the right to modify these Terms of Service at any time. Material changes will be announced on the platform in advance. Continued use of the service constitutes acceptance of the updated terms.
          </Paragraph>
          <Paragraph>
            We recommend periodically reviewing this page for the latest terms. The most current version will always be published here.
          </Paragraph>
        </div>
      ),
    },
  ];

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
        <meta
          name="description"
          content={
            isChinese
              ? `${siteName} 服务条款 — 使用规则、API 条款、免责声明与责任限制`
              : `${siteName} Terms of Service — usage policy, API terms, disclaimers, and liability limitations`
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
                <RiFileTextLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {isChinese
                    ? "使用规则 · API 条款 · 免责声明"
                    : "Usage policy · API terms · Disclaimer"}
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="glass-panel border border-border rounded-xl p-5 relative overflow-hidden"
            >
              <div className="absolute inset-x-0 top-0 h-20 bg-gradient-to-b from-primary/4 to-transparent pointer-events-none" />
              <div className="relative z-10">
                <p className="text-[13px] text-muted-foreground leading-relaxed">
                  {isChinese
                    ? `最后更新：2024 年 12 月。使用 ${siteName} 服务，即表示您同意以下服务条款。请仔细阅读以下内容，如有疑问请联系我们。`
                    : `Last updated: December 2024. By using ${siteName}, you agree to the following Terms of Service. Please read carefully — contact us if you have any questions.`}
                </p>
              </div>
            </motion.div>

            {sections.map((section, i) => (
              <motion.div
                key={section.title}
                custom={i + 1}
                initial="hidden"
                animate="visible"
                variants={card}
                className="glass-panel border border-border rounded-xl overflow-hidden"
              >
                <div className="p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <div className={`p-1.5 rounded-lg shrink-0 ${section.color}`}>
                      <section.icon className="w-4 h-4" />
                    </div>
                    <h2 className="text-sm font-semibold leading-none">
                      {isChinese ? section.title : section.titleEn}
                    </h2>
                  </div>
                  <div className="pl-9">
                    {isChinese ? section.content : section.contentEn}
                  </div>
                </div>
              </motion.div>
            ))}

            {contactEmail && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: (sections.length + 1) * 0.06, duration: 0.3 }}
                className="glass-panel border border-border rounded-xl p-5"
              >
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded-lg bg-muted/60 text-muted-foreground shrink-0">
                    <RiMailLine className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold leading-none mb-1">
                      {isChinese ? "联系我们" : "Contact Us"}
                    </p>
                    <p className="text-[12px] text-muted-foreground">
                      {isChinese
                        ? "如对本服务条款有任何疑问，欢迎通过邮件与我们联系。"
                        : "If you have any questions about these Terms of Service, feel free to reach out by email."}
                    </p>
                    <a
                      href={`mailto:${contactEmail}`}
                      className="inline-flex items-center gap-1 text-[11px] font-medium mt-2 px-2.5 py-1 rounded-md bg-muted/60 hover:bg-muted border border-border transition-colors text-muted-foreground hover:text-foreground"
                    >
                      <RiMailLine className="w-3 h-3" />
                      {contactEmail}
                    </a>
                  </div>
                </div>
              </motion.div>
            )}
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
