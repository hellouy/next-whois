import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine,
  RiShieldLine,
  RiDatabase2Line,
  RiEyeLine,
  RiFileLockLine,
  RiUserLine,
  RiServerLine,
  RiMailLine,
  RiTimeLine,
  RiLockPasswordLine,
} from "@remixicon/react";

const card = {
  hidden: { opacity: 0, y: 10 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.06, duration: 0.3 },
  }),
};

type Section = {
  icon: React.ElementType;
  color: string;
  title: string;
  titleEn: string;
  content: React.ReactNode;
  contentEn: React.ReactNode;
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

export default function PrivacyPage() {
  const settings = useSiteSettings();
  const { locale, t } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || settings.site_title || "WHOIS";
  const pageTitle = t("nav_privacy");
  const contactEmail = settings.about_contact_email || settings.admin_email || "";

  const sections: Section[] = [
    {
      icon: RiDatabase2Line,
      color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
      title: "我们收集哪些信息",
      titleEn: "Information We Collect",
      content: (
        <div className="space-y-3">
          <Paragraph>
            我们遵循最小化数据收集原则，仅收集提供服务所必需的信息：
          </Paragraph>
          <BulletList items={[
            "查询请求：您提交的域名、IP 地址、ASN 等查询内容，用于执行查询并短暂缓存结果（通常 1 小时内自动过期）。",
            "IP 地址：用于速率限制功能（防止滥用），不会与查询内容关联存储。",
            "账户信息（如已注册）：邮箱地址、加密密码，用于账户认证和域名订阅提醒功能。",
            "语言偏好：通过 Cookie 存储您选择的界面语言（如中文/英文），不涉及个人身份识别。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>
            We follow minimal data collection principles and only collect information necessary to provide the service:
          </Paragraph>
          <BulletList items={[
            "Query requests: Domain names, IP addresses, ASNs you submit, used to execute lookups and briefly cache results (typically auto-expiring within 1 hour).",
            "IP address: Used for rate limiting (abuse prevention) and not stored in association with query content.",
            "Account information (if registered): Email address and encrypted password, used for account authentication and domain expiry reminder features.",
            "Language preference: Stored via cookie to remember your chosen interface language (e.g. Chinese/English) — no personal identification involved.",
          ]} />
        </div>
      ),
    },
    {
      icon: RiEyeLine,
      color: "bg-purple-100 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400",
      title: "我们如何使用信息",
      titleEn: "How We Use Information",
      content: (
        <div className="space-y-3">
          <Paragraph>收集的信息仅用于以下目的：</Paragraph>
          <BulletList items={[
            "执行查询请求并返回结果。",
            "通过缓存机制提高查询响应速度，减少对 WHOIS/RDAP 注册管理机构服务器的请求频率。",
            "实施速率限制，防止服务被滥用。",
            "发送域名到期提醒邮件（仅对已注册并开启提醒功能的用户）。",
            "分析匿名化的服务使用统计（如查询量趋势），用于改进服务性能。",
          ]} />
          <Paragraph>我们不会将您的信息出售、出租或以任何形式向第三方提供用于商业目的。</Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>Collected information is used solely for the following purposes:</Paragraph>
          <BulletList items={[
            "Executing lookup requests and returning results.",
            "Improving query response speed through caching, reducing request frequency to WHOIS/RDAP registry servers.",
            "Implementing rate limiting to prevent service abuse.",
            "Sending domain expiry reminder emails (only for registered users who have enabled this feature).",
            "Analyzing anonymized service usage statistics (e.g. query volume trends) to improve service performance.",
          ]} />
          <Paragraph>We do not sell, rent, or otherwise share your information with third parties for commercial purposes.</Paragraph>
        </div>
      ),
    },
    {
      icon: RiFileLockLine,
      color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
      title: "Cookie 使用",
      titleEn: "Cookie Usage",
      content: (
        <div className="space-y-3">
          <Paragraph>本平台使用少量 Cookie，均为功能性必要 Cookie，不用于追踪或广告目的：</Paragraph>
          <BulletList items={[
            "NEXT_LOCALE：存储您选择的界面语言，确保语言偏好在访问间保持一致。",
            "next-auth.session-token（如已登录）：用于维持登录会话状态，会话结束后失效。",
            "查询历史（可选，localStorage）：在您的浏览器本地存储最近的查询记录，不会上传至服务器。",
          ]} />
          <Paragraph>您可以通过浏览器设置禁用 Cookie，但这可能影响语言偏好和登录功能。</Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>This platform uses a small number of cookies, all of which are functionally necessary and not used for tracking or advertising:</Paragraph>
          <BulletList items={[
            "NEXT_LOCALE: Stores your chosen interface language to maintain language preference across visits.",
            "next-auth.session-token (if logged in): Maintains your login session state and expires when the session ends.",
            "Query history (optional, localStorage): Stores recent queries locally in your browser — never uploaded to servers.",
          ]} />
          <Paragraph>You can disable cookies via your browser settings, though this may affect language preferences and login functionality.</Paragraph>
        </div>
      ),
    },
    {
      icon: RiServerLine,
      color: "bg-cyan-100 dark:bg-cyan-950/40 text-cyan-600 dark:text-cyan-400",
      title: "第三方服务",
      titleEn: "Third-Party Services",
      content: (
        <div className="space-y-3">
          <Paragraph>为提供查询服务，我们会向以下第三方发送您的查询内容（域名/IP/ASN）：</Paragraph>
          <BulletList items={[
            "RDAP 服务器：各域名注册管理机构的官方 RDAP 端点（如 IANA、VeriSign 等），用于获取域名注册信息。",
            "WHOIS 服务器：各 TLD 对应的 WHOIS 服务器，在 RDAP 不可用时作为备选。",
            "DNS 解析服务：Google、Cloudflare、Quad9、AdGuard 的 DoH 服务，用于 DNS 记录查询。",
            "IP 地理位置服务：用于 IP 地址归属地和 ASN 信息查询的第三方 API。",
            "域名价格数据：nazhumi.com、miqingju.com，提供注册价格参考数据。",
            "Supabase（数据库）：存储用户账户和订阅提醒数据，服务器位于 AWS 海外区域。",
            "Upstash / Redis（缓存）：存储查询结果缓存，自动过期，不持久化用户数据。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>To provide lookup services, we send your query content (domain/IP/ASN) to the following third parties:</Paragraph>
          <BulletList items={[
            "RDAP servers: Official RDAP endpoints of domain registries (e.g. IANA, VeriSign), for retrieving domain registration data.",
            "WHOIS servers: TLD-specific WHOIS servers used as fallback when RDAP is unavailable.",
            "DNS resolution: Google, Cloudflare, Quad9, and AdGuard DoH services for DNS record lookups.",
            "IP geolocation services: Third-party APIs for IP address geolocation and ASN information.",
            "Domain pricing data: nazhumi.com, miqingju.com, for domain registration price references.",
            "Supabase (database): Stores user account and subscription reminder data on AWS servers overseas.",
            "Upstash / Redis (cache): Stores query result cache with automatic expiry — user data is not persisted.",
          ]} />
        </div>
      ),
    },
    {
      icon: RiTimeLine,
      color: "bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400",
      title: "数据保留期限",
      titleEn: "Data Retention",
      content: (
        <div className="space-y-3">
          <BulletList items={[
            "查询缓存：通常 1 小时自动过期，最长不超过 24 小时。",
            "速率限制计数：按时间窗口（通常 1 分钟）自动清除，不持久存储。",
            "用户账户数据：在账户注销后 30 天内删除。",
            "订阅提醒设置：与账户同步，账户注销时一并删除。",
            "匿名化统计数据：可能以聚合形式保留用于服务改进，不包含任何可识别个人身份的信息。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <BulletList items={[
            "Query cache: Typically expires within 1 hour, maximum 24 hours.",
            "Rate limit counters: Automatically cleared by time window (typically 1 minute), not persisted.",
            "User account data: Deleted within 30 days of account deletion.",
            "Subscription reminder settings: Synced with the account and deleted upon account deletion.",
            "Anonymized statistics: May be retained in aggregated form for service improvement — contains no personally identifiable information.",
          ]} />
        </div>
      ),
    },
    {
      icon: RiUserLine,
      color: "bg-indigo-100 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400",
      title: "您的权利",
      titleEn: "Your Rights",
      content: (
        <div className="space-y-3">
          <Paragraph>您对自己的数据拥有以下权利：</Paragraph>
          <BulletList items={[
            "查阅权：申请查阅我们持有的与您账户相关的数据。",
            "更正权：更正您账户中不准确的信息。",
            "删除权：申请删除您的账户及所有相关数据（账户设置中可直接操作）。",
            "数据可携权：申请以常见格式导出您的账户数据（如订阅提醒列表）。",
            "撤回同意：随时关闭邮件提醒等可选功能。",
          ]} />
          <Paragraph>如需行使上述权利或有任何隐私相关问题，请通过以下方式联系我们。</Paragraph>
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <Paragraph>You have the following rights regarding your data:</Paragraph>
          <BulletList items={[
            "Right to access: Request access to data we hold about your account.",
            "Right to rectification: Correct inaccurate information in your account.",
            "Right to erasure: Request deletion of your account and all associated data (also available directly in account settings).",
            "Right to data portability: Request export of your account data in a common format (e.g. subscription reminder list).",
            "Right to withdraw consent: Disable optional features such as email reminders at any time.",
          ]} />
          <Paragraph>To exercise these rights or for any privacy-related questions, please contact us using the information below.</Paragraph>
        </div>
      ),
    },
    {
      icon: RiLockPasswordLine,
      color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
      title: "安全措施",
      titleEn: "Security Measures",
      content: (
        <div className="space-y-3">
          <BulletList items={[
            "所有通信使用 HTTPS/TLS 加密传输。",
            "用户密码使用行业标准算法（bcrypt）加密存储，原始密码不会以任何形式保存。",
            "数据库访问仅限服务器端，不对外暴露直接数据库连接。",
            "API 接口实施速率限制，防止暴力破解和滥用。",
            "定期审查和更新依赖包，修复已知安全漏洞。",
          ]} />
        </div>
      ),
      contentEn: (
        <div className="space-y-3">
          <BulletList items={[
            "All communications are encrypted using HTTPS/TLS.",
            "User passwords are encrypted using industry-standard algorithms (bcrypt) — raw passwords are never stored in any form.",
            "Database access is restricted to server-side only with no direct external database connections exposed.",
            "API endpoints implement rate limiting to prevent brute force attacks and abuse.",
            "Dependencies are regularly reviewed and updated to address known security vulnerabilities.",
          ]} />
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
              ? `${siteName} 隐私政策 — 数据收集、使用方式、Cookie 说明及您的隐私权利`
              : `${siteName} Privacy Policy — data collection, usage, cookies, and your privacy rights`
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
                <RiShieldLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {isChinese
                    ? "数据收集 · Cookie 使用 · 您的权利"
                    : "Data collection · Cookie usage · Your rights"}
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
                    ? `最后更新：2024 年 12 月。本隐私政策说明了 ${siteName} 如何收集、使用和保护您的信息。我们承诺尊重您的隐私，仅收集提供服务所必需的最少量数据。`
                    : `Last updated: December 2024. This Privacy Policy explains how ${siteName} collects, uses, and protects your information. We are committed to respecting your privacy and collecting only the minimum data necessary to provide the service.`}
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
                      ? "如有隐私相关问题或数据请求，请发送邮件联系我们。"
                      : "For privacy-related questions or data requests, please contact us by email."}
                  </p>
                  {contactEmail && (
                    <a
                      href={`mailto:${contactEmail}`}
                      className="inline-flex items-center gap-1 text-[11px] font-medium mt-2 px-2.5 py-1 rounded-md bg-muted/60 hover:bg-muted border border-border transition-colors text-muted-foreground hover:text-foreground"
                    >
                      <RiMailLine className="w-3 h-3" />
                      {contactEmail}
                    </a>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
