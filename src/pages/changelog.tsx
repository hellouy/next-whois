import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";

import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine,
  RiHistoryLine,
  RiAddCircleLine,
  RiToolsLine,
  RiBugLine,
  RiFlashlightLine,
  RiStarLine,
  RiCalendarLine,
} from "@remixicon/react";

type ChangeType = "feature" | "fix" | "improve" | "new";

interface Change {
  type: ChangeType;
  zh: string;
  en: string;
}

interface Version {
  version: string;
  date: string;
  highlight?: boolean;
  changes: Change[];
}

interface DynamicEntry {
  id: string;
  entry_date: string; // "YYYY-MM-DD"
  type: ChangeType;
  zh: string;
  en: string;
  version: string | null;
}

const VERSIONS: Version[] = [
  {
    version: "3.22",
    date: "2026-03-24",
    highlight: true,
    changes: [
      { type: "fix", zh: "订阅权限跨设备/跨会话失效修复：后台从数据库实时读取权限，JWT 过期时自动修复，无需重新登录", en: "Fix cross-device/session subscription access: DB-authoritative check with auto-heal, no re-login needed" },
    ],
  },
  {
    version: "3.21",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "用户中心合并为单一 API 端点：订阅列表、品牌认领、TLD 配置四个数据库查询完全并行，首屏数据大幅加速", en: "Dashboard merged to single API endpoint: subscriptions, stamps and TLD config fetched in parallel" },
      { type: "improve", zh: "用户中心 60 秒客户端缓存：页面内导航切换立即显示缓存数据，后台静默刷新，彻底消除重复加载转圈", en: "60-second client cache for Dashboard: instant data on re-visit, silent background refresh" },
    ],
  },
  {
    version: "3.20",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "致谢页各项目展示真实 favicon（Google Favicon 服务），无法加载时自动回退默认图标", en: "About page: real favicons via Google Favicon service with graceful fallback icon" },
      { type: "improve", zh: "更新记录页全面重设计：竖向时间线布局、超大版本号、彩色 NEW / IMPROVE / FIX 标签", en: "Changelog page redesigned: vertical timeline, large version numbers, colored type badges" },
    ],
  },
  {
    version: "3.19",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "域名查询缓存分级精细化：到期 > 180 天 → 12 小时；> 60 天 → 6 小时；≤ 7 天 → 30 分钟，减少稳定域名重复查询", en: "Tiered query cache: >180 d expiry → 12 h; >60 d → 6 h; ≤7 d → 30 min — cuts redundant lookups" },
    ],
  },
  {
    version: "3.18",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "OG 图片响应加入 Cache-Control 头（s-maxage=3600），相同 URL 首次生成后由 CDN 直接命中，无需再走 Edge Function", en: "OG images: Cache-Control s-maxage=3600 so CDN serves repeat requests without hitting Edge Function" },
    ],
  },
  {
    version: "3.17",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "匿名查询记录上限取消：原 50 条硬上限移除，所有匿名查询永久保存，同 IP 同查询自动去重", en: "Anonymous query cap removed: all queries stored permanently with same-IP deduplication" },
      { type: "new", zh: "管理后台查询记录新增「已登录用户」筛选标签，与「全部」/「匿名查询」并列，数量角标实时准确", en: "Admin search records: new Logged-in filter tab alongside All / Anonymous with live badge counts" },
    ],
  },
  {
    version: "3.16",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "订阅卡片全面升级：生命周期进度条 + 阶段提示文字 + 下次提醒日期 + 可调节提醒间隔（7/14/30/60/90 天，即点即存）", en: "Subscription cards redesigned: lifecycle progress bar, phase label, next reminder date, editable interval (7–90 d)" },
      { type: "improve", zh: "订阅标签页新增统计概览芯片（有效/即将到期/紧急/已过期）及高亮提醒横幅，列出受影响域名", en: "Subscriptions tab: summary chips (active/due soon/urgent/expired) and reminder banner listing affected domains" },
    ],
  },
  {
    version: "3.15",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "API lookup 精准识别域名/IPv4/IPv6/ASN/CIDR 查询类型，全用户高价值域名检测与告警", en: "API lookup: precise type detection for domain/IPv4/IPv6/ASN/CIDR with high-value domain flagging" },
    ],
  },
  {
    version: "3.14",
    date: "2026-03-24",
    changes: [
      { type: "new", zh: "TLD 生命周期管理页新增主流 TLD 内置参考数据表，一键对照修改覆盖规则", en: "TLD lifecycle page: built-in reference table for popular TLDs, one-click to apply as override" },
    ],
  },
  {
    version: "3.13",
    date: "2026-03-24",
    changes: [
      { type: "fix", zh: "修复公告横幅与导航栏重叠遮挡问题", en: "Fix announcement banner overlapping the navbar" },
      { type: "new", zh: "管理后台提醒支持内联编辑到期日 + 直接触发测试邮件发送", en: "Admin reminders: inline expiry date editing and direct test-email trigger" },
    ],
  },
  {
    version: "3.12",
    date: "2026-03-24",
    changes: [
      { type: "fix", zh: "修复已登录用户查询历史未正确记录的问题（lookup API 鉴权判断错位）", en: "Fix logged-in users' search history not being recorded correctly (auth check misplacement in lookup API)" },
    ],
  },
  {
    version: "3.11",
    date: "2026-03-24",
    changes: [
      { type: "improve", zh: "WHOIS 解析新增多语言域名状态字符串支持（保留/禁用/暂停等多语言变体）", en: "WHOIS parser: multi-language domain status string support (reserved/prohibited/suspended variants)" },
    ],
  },
  {
    version: "3.10",
    date: "2026-03-24",
    changes: [
      { type: "new", zh: "OG 图片文字可编辑：品牌名称、标语在后台实时修改，即时生效", en: "OG images: brand name and tagline editable in admin, takes effect immediately" },
      { type: "improve", zh: "OG 图片所有 8 种样式的品牌名 / 标语统一读取配置，不再硬编码", en: "OG: all 8 styles read brand name/tagline from config — no more hardcoded values" },
      { type: "new", zh: "更新记录后台新增「同步版本历史」按钮，自动导入缺失条目", en: "Admin changelog: Sync Version History button to auto-import missing entries to DB" },
      { type: "improve", zh: "用户搜索历史隐藏高价值 / 有价值域名标签（数据仍后台记录）", en: "Search history: high-value domain labels hidden from users (still recorded in admin)" },
    ],
  },
  {
    version: "3.9",
    date: "2026-03-24",
    changes: [
      { type: "new", zh: "API Key 管理系统：支持生成、吊销、范围管理（api / subscription / all）", en: "API Key system: generate, revoke and manage keys by scope (api / subscription / all)" },
      { type: "new", zh: "管理后台新增「密钥」页面，提供 Key 生成 / 启停 / 删除 / 使用统计", en: "Admin: new Access Keys page with generation, enable/disable, delete and usage stats" },
      { type: "feature", zh: "所有公开 API（WHOIS / DNS / SSL / IP）支持 X-API-Key 鉴权，全局可开关", en: "All public APIs (WHOIS/DNS/SSL/IP) support X-API-Key auth with global toggle" },
      { type: "improve", zh: "文档页新增「API Key 鉴权」章节，说明传参方式、权限范围及错误码", en: "Docs: new API Key Auth section covering header format, scopes and error codes" },
    ],
  },
  {
    version: "3.8",
    date: "2026-03-23",
    changes: [
      { type: "fix", zh: "修复页面切换动画失效问题（animationKey 逻辑错误）", en: "Fix page transition animation broken by animationKey logic error" },
      { type: "fix", zh: "修复 DNS / SSL / IP 工具页 URL 参数在首次渲染时被忽略的问题", en: "Fix DNS/SSL/IP tool pages ignoring URL params on initial render" },
      { type: "new", zh: "DNS / IP / SSL API 新增限流保护（60 / 30 / 20 次/分钟）", en: "DNS/IP/SSL APIs: rate limiting added (60/30/20 req/min respectively)" },
      { type: "fix", zh: "修复站点名称水合不一致导致首屏闪烁的问题", en: "Fix site name hydration mismatch causing first-render flash" },
    ],
  },
  {
    version: "3.7",
    date: "2026-03-23",
    changes: [
      { type: "improve", zh: "Redis 缓存升级为智能 TTL 策略：按域名类型自适应缓存时长", en: "Redis cache: smart adaptive TTL based on domain type" },
      { type: "improve", zh: "新增 L1（内存 30s）+ L2（Redis 自适应）双层缓存架构", en: "New two-tier cache: L1 in-memory 30 s + L2 Redis adaptive TTL" },
    ],
  },
  {
    version: "3.6",
    date: "2026-03-22",
    changes: [
      { type: "new", zh: "新增 WHOIS 限流（60 次/分钟）并引入 429 响应", en: "WHOIS rate limiting: 60 req/min with proper 429 response" },
      { type: "improve", zh: "文档页「限流规则」表格更新为实际阈值", en: "Docs: rate-limit table updated with accurate per-endpoint values" },
    ],
  },
  {
    version: "3.5",
    date: "2026-03-22",
    changes: [
      { type: "new", zh: "提醒管理后台：批量操作、状态筛选、到期日范围查询", en: "Admin reminders: bulk actions, status filters, expiry date range search" },
      { type: "improve", zh: "提醒列表新增「上次发送时间」列，支持重新触发测试邮件", en: "Reminder list: Last Sent column added with re-trigger test email button" },
    ],
  },
  {
    version: "3.4",
    date: "2026-03-22",
    changes: [
      { type: "new", zh: "用户管理后台：用户列表、禁用/解禁、权限查看与分配", en: "Admin user management: list, disable/enable, view and assign permissions" },
      { type: "new", zh: "品牌认领管理后台：审核、强制验证、批量清除失效认领", en: "Admin brand stamps: review, force-verify and bulk-clear expired claims" },
    ],
  },
  {
    version: "3.3",
    date: "2026-03-22",
    changes: [
      { type: "new", zh: "用户反馈系统：前台在线提交反馈，管理后台按类别分类处理与状态流转", en: "User feedback system: in-app submission with admin category management and status workflow" },
      { type: "new", zh: "TLD 兜底 WHOIS 服务器：管理后台可自定义任意 TLD 的解析入口，解决小众 TLD 查询失败", en: "TLD fallback WHOIS servers: admin can set custom resolver for any TLD to fix niche TLD failures" },
    ],
  },
  {
    version: "3.2",
    date: "2026-03-21",
    changes: [
      { type: "new", zh: "系统状态监控页：数据库 / 邮件 / Redis 连通性实时检查，管理员一览全局健康", en: "System status page: real-time DB / email / Redis connectivity check for admins" },
      { type: "new", zh: "站点公告功能：管理后台发布通知，用户首页顶部横幅实时展示", en: "Site announcements: publish notices in admin, displayed as a top banner on the homepage" },
    ],
  },
  {
    version: "3.1",
    date: "2026-03-21",
    changes: [
      { type: "new", zh: "Vercel 平台集成：域名 DNS 配置一键检测，自动比对 Vercel 所需记录与当前解析", en: "Vercel integration: one-click DNS check comparing required vs actual records" },
      { type: "improve", zh: "Vercel 域名绑定助手：检测缺失记录并提供精确补全指引", en: "Vercel domain helper: detects missing records and provides step-by-step fix guide" },
    ],
  },
  {
    version: "3.0",
    date: "2026-03-21",
    changes: [
      { type: "new", zh: "价格页面：多套餐定价方案对比，区分月付/年付与功能权限", en: "Pricing page: multi-plan comparison with monthly/annual billing and feature breakdown" },
      { type: "new", zh: "赞助商展示系统：首页赞助商位，管理后台增删改查、排序、显示控制", en: "Sponsor showcase: homepage sponsor slots with full admin CRUD, sort and visibility control" },
    ],
  },
  {
    version: "2.4",
    date: "2026-03-20",
    changes: [
      { type: "new", zh: "天虎平台集成：域名评估报告接入，查询结果页展示估值与市场参考", en: "Tianhu integration: domain appraisal report on lookup result pages" },
      { type: "improve", zh: "查询结果页新增「域名估值」模块，联动天虎 API 实时拉取数据", en: "Lookup results: Domain Valuation module with live Tianhu API data" },
    ],
  },
  {
    version: "2.3",
    date: "2026-03-20",
    changes: [
      { type: "new", zh: "查询历史系统：已登录用户自动记录每次查询，管理后台可查看所有用户历史", en: "Search history: auto-recorded for logged-in users; admin can view all users' history" },
      { type: "new", zh: "管理后台「查询记录」页面：全量历史、域名/用户筛选、匿名标注", en: "Admin Search Records: full history with domain/user filters and anonymous flagging" },
    ],
  },
  {
    version: "2.2",
    date: "2026-03-20",
    highlight: false,
    changes: [
      { type: "new", zh: "OG 图片 8 种视觉样式：极简网格、渐变侧栏、终端暗色、品牌顶栏、极致留白、工程蓝图、报刊版式、类型渐变", en: "8 distinct OG image styles: Minimal Grid, Gradient Panel, Terminal Dark, Header Bar, Premium Dark, Blueprint, Editorial Frame, Type Gradient" },
      { type: "new", zh: "后台 OG 卡片样式管理：预览全部样式、一键启用/停用、多选配置，按域名哈希随机选取已启用样式", en: "Admin OG style management: preview all styles, enable/disable individually, hash-based random selection from enabled styles" },
      { type: "new", zh: "OG 预览模式（?preview=1）：跳过 WHOIS 查询加速后台预览加载，5 分钟缓存减少数据库压力", en: "OG preview mode (?preview=1): skip WHOIS lookup for fast admin preview with 5-minute DB cache" },
      { type: "new", zh: "OG 样式通过 ?style=0-7 参数精确指定，方便外部调用与测试", en: "OG style override via ?style=0-7 param for precise external control and testing" },
      { type: "improve", zh: "工程蓝图样式：深蓝网格背景 + 青色四角标记 + 等宽字体，独特的技术蓝图质感", en: "Blueprint style: deep-blue grid background, cyan corner marks, monospace font — unique engineering aesthetic" },
      { type: "improve", zh: "报刊版式样式：米白底色 + 黑色内嵌边框 + 全大写域名，呈现经典印刷排版感", en: "Editorial Frame style: off-white background, inset black border, uppercase domain — classic print typography" },
      { type: "improve", zh: "类型渐变样式：按查询类型（域名/IPv4/IPv6/ASN/CIDR）自动切换配色渐变背景", en: "Type Gradient style: gradient background auto-switches by query type (DOMAIN/IPv4/IPv6/ASN/CIDR)" },
    ],
  },
  {
    version: "2.1",
    date: "2026-03-16",
    highlight: false,
    changes: [
      { type: "new", zh: "ICP 备案查询：支持网站 / APP / 小程序 / 快应用及对应违规类型，分页展示全量结果", en: "ICP filing query: supports website/app/mini-program/quick-app and blacklist types with paginated results" },
      { type: "new", zh: "ICP 查询实时状态检测：页面顶部 API 健康徽章（在线/离线/检测中），离线时自动显示提示横幅", en: "ICP query health badge: real-time online/offline/checking indicator in page header with offline warning banner" },
      { type: "new", zh: "动态更新记录系统：管理员可在后台增删改更新日志，前台按版本号合并展示", en: "Dynamic changelog system: admin can create/edit/delete changelog entries; front end merges them by version" },
      { type: "new", zh: "更新记录邮件订阅：用户可订阅新版本推送，管理员一键发送版本通知邮件", en: "Changelog email subscription: users subscribe to release notifications; admin can broadcast with one click" },
      { type: "improve", zh: "API 文档全面重构：新增分类快速导航栏、分类小节标题、/api/lookup 扩展为 5 种查询类型", en: "API docs overhaul: quick-nav pills, category section headers, /api/lookup expanded to 5 query types" },
      { type: "improve", zh: "API 文档新增 /api/dns/txt 独立端点说明及与 /api/dns/records 的对比表格", en: "API docs: /api/dns/txt documented with comparison table against /api/dns/records" },
      { type: "improve", zh: "API 文档新增精准限流速率表格（/api/lookup 40 次/分钟等各端点独立标注）", en: "API docs: per-endpoint rate-limit table with accurate values (40 req/min for /api/lookup etc.)" },
      { type: "improve", zh: "API 文档请求示例全部使用站点实际域名替代占位符 your-domain.com", en: "API docs: all code examples now use the actual site domain instead of the placeholder your-domain.com" },
      { type: "improve", zh: "ICP 查询页面加载动画改为叠加层覆盖，结果区域保持高度稳定，无跳动感", en: "ICP page: loading overlay replaces content swap — result area holds its height with no layout shift" },
    ],
  },
  {
    version: "2.0",
    date: "2026-03-12",
    changes: [
      { type: "new", zh: "友情链接后台管理：数据库驱动，支持增删改查、显示/隐藏、分类分组、排序", en: "Friendly Links admin: DB-backed CRUD with show/hide toggle, category grouping, custom sort order" },
      { type: "new", zh: "关于我们页面全面可编辑：中/英简介、联系邮箱、GitHub 链接、原作者信息均可在管理后台配置", en: "About page fully admin-editable: zh/en intro, contact email, GitHub URL, author info all configurable" },
      { type: "new", zh: "致谢列表支持 JSON 自定义，留空使用内置默认，无需改代码", en: "Acknowledgements list supports JSON override; defaults preserved when field is empty" },
      { type: "new", zh: "原作者感谢卡片恢复：GitHub 链接 + 作者主页均可在管理设置中替换", en: "Author credit card restored with configurable GitHub repo and author homepage links" },
      { type: "new", zh: "人机验证（CAPTCHA）集成：支持 Cloudflare Turnstile 和 hCaptcha，管理后台配置密钥即生效", en: "CAPTCHA integration: Cloudflare Turnstile and hCaptcha supported; enable by setting keys in admin" },
      { type: "new", zh: "注册邮箱 OTP 验证：发送 6 位验证码，10 分钟有效，60 秒防频繁发送", en: "Email OTP at registration: 6-digit code, 10-minute validity, 60-second resend cooldown" },
      { type: "new", zh: "邀请码系统：后台生成/管理邀请码，可设置最大使用次数，支持注册时填写或已注册用户后台申请", en: "Invite code system: admin-generated codes with max-use limits; apply at registration or from dashboard" },
      { type: "new", zh: "注册访问控制：require_invite_code 开关，开启后注册必须填写有效邀请码", en: "Registration gating: require_invite_code toggle; valid code required when enabled" },
      { type: "new", zh: "Dashboard 订阅标签：未持有邀请码时显示锁定状态，内嵌邀请码申请表单", en: "Dashboard subscription tab: locked state with inline invite-code application form when no access" },
      { type: "new", zh: "TLD 生命周期规则数据库化：管理后台可覆盖任意 TLD 的宽限期/赎回期/待删除天数", en: "DB-configurable TLD lifecycle rules: admin can override grace/redemption/pendingDelete days per TLD" },
      { type: "new", zh: "域名即将可注册提醒：待删除期内 7 天前自动发送邮件通知", en: "Drop approaching notification: email sent 7 days before predicted drop date during pendingDelete phase" },
      { type: "new", zh: "域名释放通知：进入 dropped 阶段后发送邮件并自动取消订阅", en: "Domain released notification: email sent on drop, subscription auto-deactivated" },
      { type: "feature", zh: "匿名查询去重：同一 IP 同一查询 24 小时内只记录一次，减少重复历史数据", en: "Anonymous query deduplication: same query within 24 h written only once to history" },
      { type: "improve", zh: "管理后台新增【人机验证】设置区块：服务商选择、Site Key、Secret Key 独立字段", en: "Admin Settings: new CAPTCHA section with provider dropdown, Site Key and Secret Key fields" },
      { type: "improve", zh: "管理后台新增【链接】【规则】【日志】导航项", en: "Admin nav: new Links, Rules, and Changelog entries" },
    ],
  },
  {
    version: "1.9",
    date: "2026-03-10",
    changes: [
      { type: "improve", zh: "页面切换动画精简：时长 0.28 s → 0.22 s，曲线换用 ease-out-expo，去除 scale 抖动", en: "Page transition refined: 0.28 s → 0.22 s, ease-out-expo curve, scale jitter removed" },
      { type: "improve", zh: "动画层添加 will-change: opacity, transform，浏览器提前提升 GPU 合成层", en: "Animated wrapper gains will-change: opacity, transform for early GPU layer promotion" },
      { type: "improve", zh: "新增 prefers-reduced-motion 支持：偏好减少动效的用户全站动画近乎即时", en: "prefers-reduced-motion support: all animations near-instant for users who prefer reduced motion" },
      { type: "improve", zh: "全局启用 scroll-behavior: smooth（仅限非减动效模式）", en: "Global smooth scrolling enabled (respects prefers-reduced-motion)" },
      { type: "improve", zh: "_document 新增 preconnect + dns-prefetch 预连接（汇率 API / IANA RDAP）", en: "Document head: preconnect + dns-prefetch hints for exchange-rate API and IANA RDAP" },
    ],
  },
  {
    version: "1.8",
    date: "2026-03-08",
    changes: [
      { type: "improve", zh: "WHOIS 合并等待窗口从 600 ms 压缩至 350 ms，RDAP 优先结果更快返回", en: "WHOIS merge-wait window reduced 600 → 350 ms; RDAP-first results arrive ~250 ms earlier" },
      { type: "improve", zh: "渐进式容灾触发时间从 3500 ms 提前至 3000 ms，慢 TLD 最坏情况提速 500 ms", en: "Progressive fallback trigger lowered 3 500 → 3 000 ms; worst-case 500 ms faster for slow TLDs" },
      { type: "improve", zh: "whoiser 模块在进程启动时预热加载，首次查询无模块解析开销", en: "whoiser module eagerly warm-loaded at process start — no parse overhead on first query" },
      { type: "improve", zh: "常见 2 段域名（.com/.net 等）TLD 数据库查询从 4 次减为 2 次（去重）", en: "TLD DB calls halved for 2-part domains (.com/.net…): 4 queries → 2 via deduplication" },
    ],
  },
  {
    version: "1.7",
    date: "2026-03-05",
    changes: [
      { type: "improve", zh: "查询 API 新增 IP 滑动窗口限流（每 IP 每分钟 40 次），防止滥用爬取", en: "Lookup API: IP-based sliding-window rate limiting (40 req/min) to prevent abuse" },
      { type: "improve", zh: "查询 API 严格校验 HTTP 方法（仅 GET），拒绝非法请求", en: "Lookup API: strict HTTP method validation — only GET accepted" },
      { type: "improve", zh: "查询长度上限 300 字符，拒绝含控制字符的恶意输入", en: "Query length capped at 300 chars; control characters rejected with 400" },
      { type: "improve", zh: "限流响应头标准化：X-RateLimit-Limit / Remaining / Reset 三字段", en: "Standard rate-limit headers: X-RateLimit-Limit / Remaining / Reset" },
      { type: "improve", zh: "管理后台设置保存提示说明同步延迟（当前浏览器即时 · 其他会话 60 秒内）", en: "Admin settings save button now shows sync latency note (instant in current browser, ≤60 s elsewhere)" },
      { type: "feature", zh: "新增四项访问控制开关：禁用登录 / 维护模式 / 纯查询模式 / 隐藏原始 WHOIS", en: "Four new access-control toggles: disable login, maintenance mode, query-only mode, hide raw WHOIS" },
    ],
  },
  {
    version: "1.6",
    date: "2026-03-01",
    changes: [
      { type: "new", zh: "域名价值评分系统：100 分制多维评估（长度/后缀/关键词/拼写模式）", en: "Domain value scoring: 100-point multi-dimensional evaluation (length/TLD/keywords/pattern)" },
      { type: "new", zh: "支持后缀页：IANA 全量 1436 个 TLD，含 248 ccTLD + 1188 gTLD", en: "TLDs page: full IANA list of 1436 TLDs including 248 ccTLD and 1188 gTLD" },
      { type: "new", zh: "支持后缀页支持 ccTLD / gTLD 分类筛选，统计卡片可点击切换", en: "TLDs page: filterable by ccTLD/gTLD via clickable stat cards" },
      { type: "new", zh: "支持后缀页标注 WHOIS / RDAP 双协议支持情况，ccTLD 显示国家名称", en: "TLDs page: WHOIS/RDAP badge indicators per TLD with ccTLD country name display" },
      { type: "new", zh: "支持后缀页整合 IANA RDAP bootstrap 数据，gTLD 默认展示 RDAP 支持", en: "TLDs page: integrated IANA RDAP bootstrap data; gTLDs show RDAP support by default" },
      { type: "new", zh: "关于我们页：项目介绍、核心功能、技术栈、二次创作声明、致谢版块", en: "About page: project intro, features, tech stack, remix declaration, and acknowledgements" },
      { type: "new", zh: "致谢版块：列出 nazhumi.com / tian.hu / miqingju.com / yisi.yun 合作方", en: "Acknowledgements: nazhumi.com / tian.hu / miqingju.com / yisi.yun listed as partners" },
      { type: "new", zh: "更新记录页：版本时间线，支持类型分类（新增/功能/优化/修复）", en: "Changelog page: version timeline with categorized change types (new/feature/improve/fix)" },
      { type: "new", zh: "友情链接页：域名行业精选工具与资源导航", en: "Friendly Links page: curated domain industry tools and resources" },
      { type: "new", zh: "工具箱全分类点击量统计，按热度永久排序", en: "Toolbox: click count tracking across all categories with persistent sort by popularity" },
      { type: "improve", zh: "移动端 iOS Safari 点击输入框自动缩放问题全站修复", en: "Fixed iOS Safari page zoom on input focus globally" },
      { type: "fix", zh: "修复横向溢出导致反馈抽屉触发偏移的问题", en: "Fixed horizontal overflow causing feedback drawer misalignment" },
    ],
  },
  {
    version: "1.5",
    date: "2026-02-05",
    changes: [
      { type: "new", zh: "Dashboard 新增订阅引导弹窗与品牌认领引导弹窗", en: "Dashboard: subscription guide modal and brand claim guide modal added" },
      { type: "new", zh: "/remind 页面：域名到期提醒管理，支持取消订阅", en: "/remind page: domain expiry reminder management with unsubscribe support" },
    ],
  },
  {
    version: "1.4",
    date: "2026-01-15",
    changes: [
      { type: "new", zh: "域名到期提醒系统：订阅后 90/30/7/1 天自动发送邮件", en: "Domain expiry reminder system: email alerts at 90/30/7/1 days before expiry" },
      { type: "new", zh: "RDAP 查询支持，优先于传统 WHOIS 协议", en: "RDAP query support, prioritized over legacy WHOIS protocol" },
      { type: "feature", zh: "域名含义翻译（基于天湖 API），支持显示英文含义", en: "Domain meaning translation (via Tianhu API) with English meaning display" },
      { type: "feature", zh: "域名市场价格标签：注册/续费/转入价格对比", en: "Domain market price tags: registration/renewal/transfer price comparison" },
      { type: "improve", zh: "查询结果页大幅重构，新增域名生命周期图", en: "Query result page overhauled, added domain lifecycle timeline" },
    ],
  },
  {
    version: "1.3",
    date: "2025-12-01",
    changes: [
      { type: "new", zh: "品牌认领（Brand Stamp）：DNS TXT 验证后展示品牌标签", en: "Brand Stamp: show verified brand tags via DNS TXT verification" },
      { type: "new", zh: "DNS 记录查询工具：A/MX/TXT/SPF/DMARC 多解析器", en: "DNS lookup tool: A/MX/TXT/SPF/DMARC multi-resolver" },
      { type: "new", zh: "SSL 证书检测工具", en: "SSL certificate checker tool" },
      { type: "feature", zh: "IP / ASN 查询：归属地 + 自治系统信息", en: "IP/ASN lookup: geolocation and autonomous system information" },
      { type: "improve", zh: "WHOIS 解析器优化，提升字段识别准确率", en: "WHOIS parser optimization, improved field recognition accuracy" },
    ],
  },
  {
    version: "1.2",
    date: "2025-11-08",
    changes: [
      { type: "new", zh: "用户系统：注册 / 登录 / 找回密码", en: "User system: register, login, forgot/reset password" },
      { type: "new", zh: "Dashboard：域名订阅管理与品牌认领列表", en: "Dashboard: domain subscription management and brand claims list" },
      { type: "feature", zh: "域名工具箱（/tools）：精选外部工具链接", en: "Domain toolbox (/tools): curated external tool links" },
      { type: "fix", zh: "修复多国 ccTLD WHOIS 服务器配置问题", en: "Fixed WHOIS server configs for multiple country ccTLDs" },
    ],
  },
  {
    version: "1.1",
    date: "2025-10-15",
    changes: [
      { type: "new", zh: "8 种语言支持：中/英/日/韩/德/法/俄/繁中", en: "8-language support: zh/en/ja/ko/de/fr/ru/zh-tw" },
      { type: "new", zh: "深色 / 浅色主题切换", en: "Dark/light theme toggle" },
      { type: "new", zh: "API 接口文档页（/docs）", en: "API documentation page (/docs)" },
      { type: "feature", zh: "CIDR 网段查询支持", en: "CIDR network range lookup support" },
      { type: "improve", zh: "移动端导航优化，底部抽屉菜单", en: "Mobile navigation optimized with bottom drawer menu" },
    ],
  },
  {
    version: "1.0",
    date: "2025-09-01",
    changes: [
      { type: "new", zh: "项目上线：域名 WHOIS 查询，支持 200+ 后缀", en: "Initial launch: domain WHOIS lookup with 200+ TLD support" },
      { type: "new", zh: "ASN 自治系统查询", en: "ASN autonomous system lookup" },
      { type: "new", zh: "IPv4 / IPv6 地址查询", en: "IPv4/IPv6 address lookup" },
      { type: "feature", zh: "PWA 支持，可安装到手机桌面", en: "PWA support for home screen installation" },
    ],
  },
];

const TYPE_CONFIG: Record<ChangeType, { icon: typeof RiAddCircleLine; color: string; label: string; labelEn: string }> = {
  new:     { icon: RiAddCircleLine,  color: "text-emerald-500", label: "新增", labelEn: "New" },
  feature: { icon: RiStarLine,       color: "text-blue-500",    label: "功能", labelEn: "Feature" },
  improve: { icon: RiFlashlightLine, color: "text-amber-500",   label: "优化", labelEn: "Improve" },
  fix:     { icon: RiBugLine,        color: "text-red-500",     label: "修复", labelEn: "Fix" },
};

function groupEntriesByMonth(entries: DynamicEntry[]): {
  monthKey: string; monthLabel: string; monthLabelEn: string;
  days: { date: string; dayLabel: string; dayLabelEn: string; items: DynamicEntry[] }[];
}[] {
  const months = new Map<string, Map<string, DynamicEntry[]>>();
  for (const e of entries) {
    const [y, m, d] = e.entry_date.split("-");
    const mk = `${y}-${m}`;
    if (!months.has(mk)) months.set(mk, new Map());
    const days = months.get(mk)!;
    if (!days.has(e.entry_date)) days.set(e.entry_date, []);
    days.get(e.entry_date)!.push(e);
    const _ = [d]; // suppress unused warning
  }
  return Array.from(months.entries()).map(([mk, days]) => {
    const [y, m] = mk.split("-");
    const mi = parseInt(m);
    return {
      monthKey: mk,
      monthLabel: `${y}年${mi}月`,
      monthLabelEn: new Date(Number(y), mi - 1, 1).toLocaleDateString("en-US", { year: "numeric", month: "long" }),
      days: Array.from(days.entries()).map(([dk, items]) => {
        const day = parseInt(dk.split("-")[2]);
        return {
          date: dk,
          dayLabel: `${mi}月${day}日`,
          dayLabelEn: new Date(Number(y), mi - 1, day).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
          items,
        };
      }).sort((a, b) => b.date.localeCompare(a.date)),
    };
  }).sort((a, b) => b.monthKey.localeCompare(a.monthKey));
}

export default function ChangelogPage() {
  const { locale } = useTranslation();
  const settings = useSiteSettings();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const siteName = settings.site_logo_text || "WHOIS";
  const [dynamicEntries, setDynamicEntries] = React.useState<DynamicEntry[]>([]);
  const [dynamicLoaded, setDynamicLoaded] = React.useState(false);

  React.useEffect(() => {
    fetch("/api/changelog")
      .then(r => r.json())
      .then(d => { setDynamicEntries(d.entries || []); setDynamicLoaded(true); })
      .catch(() => setDynamicLoaded(true));
  }, []);

  const grouped = groupEntriesByMonth(dynamicEntries);
  const totalEntries = dynamicEntries.length;

  return (
    <>
      <Head>
        <title key="title">{`${isChinese ? "更新记录" : "Changelog"} — ${siteName}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6 pb-16">
          {/* Header */}
          <div className="flex items-center gap-3 mb-6">
            <Link href="/about" className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-amber-500/10 text-amber-500">
                <RiHistoryLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">
                  {isChinese ? "更新记录" : "Changelog"}
                </h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {isChinese ? "每个版本的新功能与修复" : "Features and fixes in each release"}
                </p>
              </div>
            </div>
            <div className="ml-auto flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground hidden sm:block">
                {VERSIONS.length} {isChinese ? "个版本" : "releases"}
                {totalEntries > 0 && ` · ${totalEntries} ${isChinese ? "条动态" : "updates"}`}
              </span>
            </div>
          </div>

          {/* ── Dynamic daily updates section ── */}
          {(dynamicLoaded && grouped.length > 0) && (
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.28 }}
              className="mb-6"
            >
              <div className="flex items-center gap-2 mb-4">
                <div className="p-1 rounded bg-primary/10">
                  <RiCalendarLine className="w-3.5 h-3.5 text-primary" />
                </div>
                <span className="text-sm font-bold text-primary">
                  {isChinese ? "近期更新" : "Recent Updates"}
                </span>
                <div className="flex-1 h-px bg-primary/20" />
              </div>

              <div className="space-y-5">
                {grouped.map((month, mi) => (
                  <motion.div
                    key={month.monthKey}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.22, delay: mi * 0.05 }}
                    className="glass-panel border border-border/60 rounded-xl overflow-hidden"
                  >
                    {/* Month header */}
                    <div className="px-4 py-2.5 border-b border-border/40 bg-muted/20 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <RiToolsLine className="w-3.5 h-3.5 text-muted-foreground" />
                        <span className="text-[13px] font-bold">
                          {isChinese ? month.monthLabel : month.monthLabelEn}
                        </span>
                      </div>
                      <span className="text-[10px] text-muted-foreground">
                        {month.days.reduce((n, d) => n + d.items.length, 0)} {isChinese ? "条" : "items"}
                      </span>
                    </div>

                    {/* Days */}
                    <div className="px-4 py-3 space-y-4">
                      {month.days.map(day => (
                        <div key={day.date}>
                          <div className="flex items-center gap-2 mb-2">
                            <span className="text-[11px] font-semibold text-muted-foreground tabular-nums">
                              {isChinese ? day.dayLabel : day.dayLabelEn}
                            </span>
                            <div className="flex-1 h-px bg-border/30" />
                          </div>
                          <div className="space-y-1.5 pl-1">
                            {day.items.map(entry => {
                              const cfg = TYPE_CONFIG[entry.type] ?? TYPE_CONFIG.new;
                              return (
                                <div key={entry.id} className="flex items-start gap-2.5">
                                  <cfg.icon className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${cfg.color}`} />
                                  <span className="text-[12px] text-foreground/80 leading-snug">
                                    {isChinese ? entry.zh : (entry.en || entry.zh)}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                ))}
              </div>

              {/* Divider before version history */}
              <div className="flex items-center gap-3 mt-7 mb-5">
                <div className="flex-1 h-px bg-border/40" />
                <span className="text-[11px] text-muted-foreground/60 whitespace-nowrap">
                  {isChinese ? "版本历史" : "Version History"}
                </span>
                <div className="flex-1 h-px bg-border/40" />
              </div>
            </motion.div>
          )}

          {/* ── Static version history ── */}
          <div className="relative">
            {/* Timeline connector line */}
            <div className="absolute left-[11px] top-4 bottom-4 w-px bg-border/50 hidden sm:block" />
            <div className="space-y-5">
              {VERSIONS.map((v, vi) => (
                <motion.div
                  key={v.version}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25, delay: vi * 0.04 }}
                  className="sm:pl-9 relative"
                >
                  {/* Timeline dot */}
                  <div className={cn(
                    "absolute left-[7px] top-5 w-2.5 h-2.5 rounded-full border-2 hidden sm:block",
                    v.highlight ? "border-primary bg-primary/40" : "border-border/70 bg-background"
                  )} />

                  <div className={cn(
                    "border rounded-2xl overflow-hidden",
                    v.highlight ? "border-primary/25" : "border-border/60"
                  )}>
                    {/* Version header */}
                    <div className={cn(
                      "px-5 py-4 flex items-center justify-between gap-4",
                      v.highlight ? "bg-primary/[0.03]" : ""
                    )}>
                      <div className="flex items-center gap-3">
                        <span className={cn(
                          "text-2xl font-black font-mono tracking-tight leading-none",
                          v.highlight ? "text-primary" : "text-foreground"
                        )}>
                          v{v.version}
                        </span>
                        {v.highlight && (
                          <span className="text-[9px] font-extrabold tracking-widest uppercase px-2 py-0.5 rounded-full bg-primary text-primary-foreground">
                            {isChinese ? "最新" : "Latest"}
                          </span>
                        )}
                      </div>
                      <span className="text-xs text-muted-foreground font-mono tabular-nums">{v.date}</span>
                    </div>

                    {/* Divider */}
                    <div className={cn("h-px", v.highlight ? "bg-primary/12" : "bg-border/40")} />

                    {/* Change list */}
                    <div className="px-5 py-4 space-y-3">
                      {v.changes.map((c, ci) => {
                        const cfg = TYPE_CONFIG[c.type];
                        return (
                          <div key={ci} className="flex items-start gap-3">
                            <span className={cn(
                              "text-[9px] font-extrabold tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 uppercase whitespace-nowrap",
                              c.type === "new"     ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400" :
                              c.type === "improve" ? "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" :
                              c.type === "fix"     ? "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" :
                              "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400"
                            )}>
                              {isChinese ? cfg.label : cfg.labelEn}
                            </span>
                            <span className="text-[13px] text-foreground/85 leading-snug">
                              {isChinese ? c.zh : c.en}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>

          <div className="mt-10 pt-6 border-t border-border/40 text-center">
            <p className="text-[11px] text-muted-foreground/50">
              {isChinese ? "所有版本号遵循语义化版本规范" : "All versions follow Semantic Versioning"}
            </p>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
