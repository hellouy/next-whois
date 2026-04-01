// @ts-nocheck — This file is a pure locale-data file; `as any` casts are intentional.
/**
 * Locale-specific strings for all user-facing email templates.
 * Admin-only emails (feedback, high-value alert) remain in English.
 */

export type EmailLocale = "zh" | "zh-tw" | "en" | "de" | "ru" | "ja" | "fr" | "ko";

export const SUPPORTED_EMAIL_LOCALES = new Set<EmailLocale>(["zh", "zh-tw", "en", "de", "ru", "ja", "fr", "ko"]);

export function normalizeEmailLocale(raw: string | null | undefined): EmailLocale {
  if (!raw) return "zh";
  const l = raw.toLowerCase().trim();
  if (l === "zh-tw" || l === "zh-hk" || l === "zh-mo") return "zh-tw";
  if (l.startsWith("zh")) return "zh";
  if (SUPPORTED_EMAIL_LOCALES.has(l as EmailLocale)) return l as EmailLocale;
  return "en";
}

/** Read locale from NEXT_LOCALE cookie in an HTTP request header string */
export function localeFromCookieHeader(cookieHeader?: string): EmailLocale {
  if (!cookieHeader) return "zh";
  const m = cookieHeader.match(/(?:^|;\s*)NEXT_LOCALE=([^;]+)/);
  return normalizeEmailLocale(m?.[1]);
}

/** Read locale from Accept-Language request header */
export function localeFromAcceptHeader(acceptLang?: string): EmailLocale {
  if (!acceptLang) return "zh";
  const primary = acceptLang.split(",")[0]?.split(";")[0]?.trim().toLowerCase() ?? "";
  return normalizeEmailLocale(primary);
}

// ── String definitions ────────────────────────────────────────────────────────

export interface EmailStrings {
  // Layout / footer
  auto_sent: (siteName: string) => string;
  privacy: string;
  terms: string;
  unsubscribe: string;

  // Welcome
  w_label: string;
  w_title: (name: string | null | undefined) => string;
  w_sub: string;
  w_intro: (siteName: string) => string;
  w_features: Array<[string, string, string]>;
  w_login_label: string;
  w_cta: string;

  // Subscription confirm
  sc_label: string;
  sc_sub: string;
  sc_restricted_label: string;
  sc_restricted_sub: string;
  sc_current_status: string;
  sc_subscribed: string;
  sc_subscribed_desc: string;
  sc_expiry_date: string;
  sc_reminder_nodes: string;
  sc_phase_alerts: string;
  sc_grace_pill: string;
  sc_redemption_pill: string;
  sc_pending_pill: string;
  sc_view_domain: string;
  sc_phases: Record<string, { label: string; desc: string }>;
  sc_restricted_prohibited_desc: string;
  sc_restricted_reserved_desc: string;
  sc_prohibited_label: string;
  sc_reserved_label: string;

  // Expiry reminder
  r_urgent_label: string;
  r_label: string;
  r_sub: (n: number) => string;
  r_expiry_date: string;
  r_reg_date: string;
  r_registrar: string;
  r_nameservers: string;
  r_urgent_body: (n: number) => string;
  r_normal_body: string;
  r_cta: string;

  // Phase event
  pe_sub: string;
  pe_orig_expiry: string;
  pe_current_status: string;
  pe_grace_label: string;
  pe_grace_badge: string;
  pe_grace_body: string;
  pe_grace_urgency: string;
  pe_grace_next_label: string;
  pe_redemption_label: string;
  pe_redemption_badge: string;
  pe_redemption_body: string;
  pe_redemption_urgency: string;
  pe_redemption_next_label: string;
  pe_pending_label: string;
  pe_pending_badge: string;
  pe_pending_body: string;
  pe_pending_urgency: string;
  pe_pending_next_label: string;
  pe_reg_date: string;
  pe_registrar: string;
  pe_cta: string;

  // Drop approaching
  da_label: string;
  da_sub: string;
  da_orig_expiry: string;
  da_avail_date: string;
  da_body: string;
  da_urgency_1: string;
  da_urgency_n: (n: number) => string;
  da_cta: string;

  // Domain dropped
  dd_label: string;
  dd_sub: string;
  dd_orig_expiry: string;
  dd_available: string;
  dd_note: string;
  dd_cta: string;

  // Password reset
  pr_label: string;
  pr_title: string;
  pr_body: string;
  pr_cta: string;
  pr_link_note: string;
  pr_security: string;

  // Stamp verify timeout
  sv_label: string;
  sv_sub: string;
  sv_intro: string;
  sv_step1_title: string;
  sv_step1_body: string;
  sv_step2_title: string;
  sv_step3_title: string;
  sv_step3_body: string;
  sv_cta: string;
  sv_retry: string;

  // Email subjects
  subj_welcome: (siteName: string) => string;
  subj_sub_confirm: (domain: string) => string;
  subj_sub_restricted: (domain: string) => string;
  subj_reminder_urgent: (domain: string, days: number) => string;
  subj_reminder_warn: (domain: string, days: number) => string;
  subj_reminder: (domain: string, days: number) => string;
  subj_grace: (domain: string) => string;
  subj_redemption: (domain: string) => string;
  subj_pending: (domain: string) => string;
  subj_drop_soon: (domain: string, days: number) => string;
  subj_dropped: (domain: string) => string;
  subj_password_reset: (siteName: string) => string;
  subj_stamp_verify: (domain: string) => string;

  // Date formatting locale tag (for toLocaleDateString)
  date_locale: string;
}

const FEATURES_ZH: Array<[string, string, string]> = [
  ["🔍", "无限查询", "WHOIS / RDAP · 域名、IP、ASN、CIDR 全支持"],
  ["🔔", "到期提醒", "多节点自动推送，不错过任何续费时间"],
  ["🛡️", "品牌认领", "为您拥有的域名设置认证标签"],
  ["📊", "搜索历史", "随时回顾查询记录"],
];
const FEATURES_ZHTW: Array<[string, string, string]> = [
  ["🔍", "無限查詢", "WHOIS / RDAP · 域名、IP、ASN、CIDR 全支援"],
  ["🔔", "到期提醒", "多節點自動推送，不錯過任何續費時間"],
  ["🛡️", "品牌認領", "為您擁有的域名設置認證標籤"],
  ["📊", "搜尋歷史", "隨時回顧查詢記錄"],
];
const FEATURES_EN: Array<[string, string, string]> = [
  ["🔍", "Unlimited Queries", "WHOIS / RDAP · Domain, IP, ASN, CIDR support"],
  ["🔔", "Expiry Reminders", "Multi-threshold alerts so you never miss a renewal"],
  ["🛡️", "Brand Claims", "Certify ownership with a verified tag on your domain"],
  ["📊", "Search History", "Review your past lookups anytime"],
];
const FEATURES_DE: Array<[string, string, string]> = [
  ["🔍", "Unbegrenzte Abfragen", "WHOIS / RDAP · Domain, IP, ASN, CIDR"],
  ["🔔", "Ablauf-Erinnerungen", "Automatische Benachrichtigungen vor dem Ablaufdatum"],
  ["🛡️", "Marken-Claims", "Zertifizieren Sie Ihre Domain mit einem verifizierten Badge"],
  ["📊", "Suchverlauf", "Sehen Sie Ihre vergangenen Abfragen jederzeit ein"],
];
const FEATURES_RU: Array<[string, string, string]> = [
  ["🔍", "Неограниченные запросы", "WHOIS / RDAP · Домен, IP, ASN, CIDR"],
  ["🔔", "Напоминания об истечении", "Автоматические уведомления перед истечением срока"],
  ["🛡️", "Брендинг домена", "Подтвердите право собственности на домен"],
  ["📊", "История поиска", "Просматривайте прошлые запросы в любое время"],
];
const FEATURES_JA: Array<[string, string, string]> = [
  ["🔍", "無制限クエリ", "WHOIS / RDAP · ドメイン、IP、ASN、CIDR対応"],
  ["🔔", "有効期限リマインダー", "自動通知で更新を忘れません"],
  ["🛡️", "ブランド申請", "認証済みタグでドメインの所有権を証明"],
  ["📊", "検索履歴", "いつでも過去の検索を確認"],
];
const FEATURES_FR: Array<[string, string, string]> = [
  ["🔍", "Recherches illimitées", "WHOIS / RDAP · Domaine, IP, ASN, CIDR"],
  ["🔔", "Rappels d'expiration", "Alertes automatiques avant l'expiration"],
  ["🛡️", "Revendication de marque", "Certifiez la propriété de votre domaine"],
  ["📊", "Historique de recherche", "Consultez vos recherches passées"],
];
const FEATURES_KO: Array<[string, string, string]> = [
  ["🔍", "무제한 조회", "WHOIS / RDAP · 도메인, IP, ASN, CIDR 지원"],
  ["🔔", "만료 알림", "자동 알림으로 갱신을 놓치지 마세요"],
  ["🛡️", "브랜드 인증", "도메인 소유권을 인증 배지로 증명"],
  ["📊", "검색 기록", "언제든지 과거 검색을 확인"],
];

export const EMAIL_STRINGS: Record<EmailLocale, EmailStrings> = {

  /* ── CHINESE (SIMPLIFIED) ─────────────────────────────────────────────── */
  zh: {
    auto_sent: (siteName: string) => `此邮件由 ${siteName} 自动发送，请勿直接回复` as any,
    privacy: "隐私政策",
    terms: "服务条款",
    unsubscribe: "取消订阅",

    w_label: "欢迎加入",
    w_title: (n) => n ? `你好，${n}！` : "你好！",
    w_sub: "您的账号已成功创建",
    w_intro: (s) => `现在可以使用 ${s} 的全部功能：`,
    w_features: FEATURES_ZH,
    w_login_label: "登录邮箱：",
    w_cta: "开始查询",

    sc_label: "域名订阅确认",
    sc_sub: "我们将在到期前自动发送邮件提醒",
    sc_restricted_label: "域名状态变化订阅",
    sc_restricted_sub: "域名状态变化时，我们将第一时间通知您",
    sc_current_status: "当前状态",
    sc_subscribed: "已订阅的提醒",
    sc_subscribed_desc: "当该域名的注册状态发生任何变化时自动通知",
    sc_expiry_date: "过期日期",
    sc_reminder_nodes: "提醒节点",
    sc_phase_alerts: "生命周期阶段提醒",
    sc_grace_pill: "进入宽限期",
    sc_redemption_pill: "进入赎回期",
    sc_pending_pill: "进入待删除期",
    sc_view_domain: "查看域名",
    sc_phases: {
      active:        { label: "有效期内",  desc: "域名状态正常，到期前将自动发送提醒。" },
      grace:         { label: "宽限期",    desc: "域名已过期，仍可按正常价格续费。" },
      redemption:    { label: "赎回期",    desc: "续费费用较高，请尽快联系注册商赎回。" },
      pendingDelete: { label: "待删除",    desc: "域名即将被注册局删除，通常无法再续费。" },
      dropped:       { label: "已删除",    desc: "域名已删除，即将重新开放注册。" },
    },
    sc_prohibited_label: "禁止注册",
    sc_reserved_label: "保留域名",
    sc_restricted_prohibited_desc: "该域名被注册局标记为禁止注册字符串，通常无法通过常规渠道注册。当域名注册状态发生变化时，我们将第一时间通知您。",
    sc_restricted_reserved_desc: "该域名目前为注册局保留状态，不对公众开放注册。如域名状态变化或开放注册，我们将立即发送通知。",

    r_urgent_label: "⚠ 紧急提醒",
    r_label: "到期提醒",
    r_sub: (n) => `距离到期还有 ${n} 天`,
    r_expiry_date: "过期日期",
    r_reg_date: "注册日期",
    r_registrar: "注册商",
    r_nameservers: "域名服务器",
    r_urgent_body: (n) => `域名将在 <strong>${n} 天</strong>内过期，请立即前往注册商续费，避免进入宽限期产生额外费用。`,
    r_normal_body: "请尽快续费您的域名，以免服务因过期而中断。续费成功后可忽略此提醒。",
    r_cta: "立即查看",

    pe_sub: "域名生命周期状态变更通知",
    pe_orig_expiry: "原过期日期",
    pe_current_status: "当前状态",
    pe_grace_label: "宽限期提醒",
    pe_grace_badge: "宽限期",
    pe_grace_body: "域名已过期但仍处于宽限期，可按正常价格续费。请尽快联系注册商，以免进入赎回期产生额外费用。",
    pe_grace_urgency: "⚠ 请尽快续费",
    pe_grace_next_label: "宽限期结束",
    pe_redemption_label: "赎回期提醒",
    pe_redemption_badge: "赎回期",
    pe_redemption_body: "宽限期已结束，域名进入赎回期。赎回费用通常为正常价格的 5–10 倍，请立即联系注册商申请赎回。",
    pe_redemption_urgency: "🚨 高额赎回费，请立即操作",
    pe_redemption_next_label: "赎回期结束",
    pe_pending_label: "待删除提醒",
    pe_pending_badge: "待删除",
    pe_pending_body: "域名已进入待删除状态，通常无法再续费或赎回。删除后域名将重新向公众开放注册，如有需要可关注抢注时机。",
    pe_pending_urgency: "❌ 通常已无法续费",
    pe_pending_next_label: "预计释放时间",
    pe_reg_date: "注册日期",
    pe_registrar: "注册商",
    pe_cta: "查看域名详情",

    da_label: "域名即将可注册",
    da_sub: "该域名即将进入可注册状态",
    da_orig_expiry: "原过期日期",
    da_avail_date: "预计可注册日期",
    da_body: "域名已完成所有保留期，即将从注册局释放。若您有意注册此域名，请关注各大注册商的抢注服务，通常在释放后数小时至数天内可完成注册。",
    da_urgency_1: "🔴 明日起可抢注",
    da_urgency_n: (n) => `⚡ ${n} 天后可抢注`,
    da_cta: "查看域名详情",

    dd_label: "域名已释放",
    dd_sub: "该域名已重新开放注册",
    dd_orig_expiry: "原过期日期",
    dd_available: "✅ 域名已完成所有保留期，现已向公众开放注册。",
    dd_note: "请前往你的注册商查看是否可以注册。部分域名释放后会进入抢注竞价流程，可关注 DropCatch、NameJet 等平台。",
    dd_cta: "查看域名详情",

    pr_label: "账户安全",
    pr_title: "重置您的密码",
    pr_body: "我们收到了您的密码重置请求。点击下方按钮设置新密码，链接在 <strong>60 分钟</strong>内有效。",
    pr_cta: "重置密码",
    pr_link_note: "如果按钮无法点击，请复制以下链接到浏览器地址栏：",
    pr_security: "如非您本人操作，请忽略此邮件，您的账户安全不受影响。",

    sv_label: "域名验证超时",
    sv_sub: "DNS 验证未在规定时间内完成",
    sv_intro: "您的域名 DNS 验证已超时，请改用<strong>文件验证</strong>方式完成品牌认领。",
    sv_step1_title: "第一步 — 创建验证文件",
    sv_step1_body: "在域名根目录创建文件路径：",
    sv_step2_title: "第二步 — 文件内容（一行）",
    sv_step3_title: "第三步 — 完成验证",
    sv_step3_body: "部署文件后，点击下方按钮触发验证。",
    sv_cta: "触发文件验证",
    sv_retry: "验证完成后此提醒将自动关闭",

    subj_welcome: (s: string) => `欢迎加入 ${s}！`,
    subj_sub_confirm: (d: string) => `✅ ${d} 订阅成功 — 到期前将自动提醒`,
    subj_sub_restricted: (d: string) => `✅ ${d} 状态监控订阅成功`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 紧急 ${d} 将在 ${n} 天后到期`,
    subj_reminder_warn: (d: string, n: number) => `🟠 临近 ${d} 将在 ${n} 天后到期`,
    subj_reminder: (d: string, n: number) => `📅 ${d} 将在 ${n} 天后到期`,
    subj_grace: (d: string) => `⏰ ${d} 已进入宽限期，请尽快续费`,
    subj_redemption: (d: string) => `🚨 ${d} 已进入赎回期，赎回费用较高`,
    subj_pending: (d: string) => `❌ ${d} 即将被删除，域名进入待删除期`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} 将在 ${n} 天后可抢注`,
    subj_dropped: (d: string) => `✅ ${d} 已释放，现在可以注册了`,
    subj_password_reset: (s: string) => `${s} 密码重置请求`,
    subj_stamp_verify: (d: string) => `${d} 域名验证超时 — 请改用文件验证`,

    date_locale: "zh-CN",
  } as any,

  /* ── CHINESE (TRADITIONAL) ───────────────────────────────────────────── */
  "zh-tw": {
    auto_sent: (siteName: string) => `此郵件由 ${siteName} 自動發送，請勿直接回覆` as any,
    privacy: "隱私政策",
    terms: "服務條款",
    unsubscribe: "取消訂閱",

    w_label: "歡迎加入",
    w_title: (n) => n ? `你好，${n}！` : "你好！",
    w_sub: "您的帳號已成功建立",
    w_intro: (s) => `現在可以使用 ${s} 的全部功能：`,
    w_features: FEATURES_ZHTW,
    w_login_label: "登入信箱：",
    w_cta: "開始查詢",

    sc_label: "域名訂閱確認",
    sc_sub: "我們將在到期前自動發送郵件提醒",
    sc_restricted_label: "域名狀態變化訂閱",
    sc_restricted_sub: "域名狀態變化時，我們將第一時間通知您",
    sc_current_status: "目前狀態",
    sc_subscribed: "已訂閱的提醒",
    sc_subscribed_desc: "當該域名的註冊狀態發生任何變化時自動通知",
    sc_expiry_date: "過期日期",
    sc_reminder_nodes: "提醒節點",
    sc_phase_alerts: "生命週期階段提醒",
    sc_grace_pill: "進入寬限期",
    sc_redemption_pill: "進入贖回期",
    sc_pending_pill: "進入待刪除期",
    sc_view_domain: "查看域名",
    sc_phases: {
      active:        { label: "有效期內",  desc: "域名狀態正常，到期前將自動發送提醒。" },
      grace:         { label: "寬限期",    desc: "域名已過期，仍可按正常價格續費。" },
      redemption:    { label: "贖回期",    desc: "續費費用較高，請盡快聯絡註冊商贖回。" },
      pendingDelete: { label: "待刪除",    desc: "域名即將被註冊局刪除，通常無法再續費。" },
      dropped:       { label: "已刪除",    desc: "域名已刪除，即將重新開放註冊。" },
    },
    sc_prohibited_label: "禁止註冊",
    sc_reserved_label: "保留域名",
    sc_restricted_prohibited_desc: "該域名被註冊局標記為禁止註冊字串，通常無法透過常規管道註冊。當域名狀態發生變化時，我們將第一時間通知您。",
    sc_restricted_reserved_desc: "該域名目前為註冊局保留狀態，不對公眾開放註冊。如域名狀態變化或開放註冊，我們將立即發送通知。",

    r_urgent_label: "⚠ 緊急提醒",
    r_label: "到期提醒",
    r_sub: (n) => `距離到期還有 ${n} 天`,
    r_expiry_date: "過期日期",
    r_reg_date: "註冊日期",
    r_registrar: "註冊商",
    r_nameservers: "域名服務器",
    r_urgent_body: (n) => `域名將在 <strong>${n} 天</strong>內過期，請立即前往註冊商續費，避免進入寬限期產生額外費用。`,
    r_normal_body: "請盡快續費您的域名，以免服務因過期而中斷。續費成功後可忽略此提醒。",
    r_cta: "立即查看",

    pe_sub: "域名生命週期狀態變更通知",
    pe_orig_expiry: "原過期日期",
    pe_current_status: "目前狀態",
    pe_grace_label: "寬限期提醒",
    pe_grace_badge: "寬限期",
    pe_grace_body: "域名已過期但仍處於寬限期，可按正常價格續費。請盡快聯絡註冊商，以免進入贖回期產生額外費用。",
    pe_grace_urgency: "⚠ 請盡快續費",
    pe_grace_next_label: "寬限期結束",
    pe_redemption_label: "贖回期提醒",
    pe_redemption_badge: "贖回期",
    pe_redemption_body: "寬限期已結束，域名進入贖回期。贖回費用通常為正常價格的 5–10 倍，請立即聯絡註冊商申請贖回。",
    pe_redemption_urgency: "🚨 高額贖回費，請立即操作",
    pe_redemption_next_label: "贖回期結束",
    pe_pending_label: "待刪除提醒",
    pe_pending_badge: "待刪除",
    pe_pending_body: "域名已進入待刪除狀態，通常無法再續費或贖回。刪除後域名將重新向公眾開放註冊，如有需要可關注搶註時機。",
    pe_pending_urgency: "❌ 通常已無法續費",
    pe_pending_next_label: "預計釋放時間",
    pe_reg_date: "註冊日期",
    pe_registrar: "註冊商",
    pe_cta: "查看域名詳情",

    da_label: "域名即將可註冊",
    da_sub: "該域名即將進入可註冊狀態",
    da_orig_expiry: "原過期日期",
    da_avail_date: "預計可註冊日期",
    da_body: "域名已完成所有保留期，即將從註冊局釋放。若您有意註冊此域名，請關注各大註冊商的搶註服務。",
    da_urgency_1: "🔴 明日起可搶註",
    da_urgency_n: (n) => `⚡ ${n} 天後可搶註`,
    da_cta: "查看域名詳情",

    dd_label: "域名已釋放",
    dd_sub: "該域名已重新開放註冊",
    dd_orig_expiry: "原過期日期",
    dd_available: "✅ 域名已完成所有保留期，現已向公眾開放註冊。",
    dd_note: "請前往您的註冊商查看是否可以註冊。部分域名釋放後會進入搶註競價流程，可關注 DropCatch、NameJet 等平台。",
    dd_cta: "查看域名詳情",

    pr_label: "帳戶安全",
    pr_title: "重置您的密碼",
    pr_body: "我們收到了您的密碼重置請求。點擊下方按鈕設置新密碼，連結在 <strong>60 分鐘</strong>內有效。",
    pr_cta: "重置密碼",
    pr_link_note: "如果按鈕無法點擊，請複製以下連結到瀏覽器網址列：",
    pr_security: "如非您本人操作，請忽略此郵件，您的帳戶安全不受影響。",

    sv_label: "域名驗證超時",
    sv_sub: "DNS 驗證未在規定時間內完成",
    sv_intro: "您的域名 DNS 驗證已超時，請改用<strong>文件驗證</strong>方式完成品牌認領。",
    sv_step1_title: "第一步 — 建立驗證文件",
    sv_step1_body: "在域名根目錄建立文件路徑：",
    sv_step2_title: "第二步 — 文件內容（一行）",
    sv_step3_title: "第三步 — 完成驗證",
    sv_step3_body: "部署文件後，點擊下方按鈕觸發驗證。",
    sv_cta: "觸發文件驗證",
    sv_retry: "驗證完成後此提醒將自動關閉",

    subj_welcome: (s: string) => `歡迎加入 ${s}！`,
    subj_sub_confirm: (d: string) => `✅ ${d} 訂閱成功 — 到期前將自動提醒`,
    subj_sub_restricted: (d: string) => `✅ ${d} 狀態監控訂閱成功`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 緊急 ${d} 將在 ${n} 天後到期`,
    subj_reminder_warn: (d: string, n: number) => `🟠 臨近 ${d} 將在 ${n} 天後到期`,
    subj_reminder: (d: string, n: number) => `📅 ${d} 將在 ${n} 天後到期`,
    subj_grace: (d: string) => `⏰ ${d} 已進入寬限期，請盡快續費`,
    subj_redemption: (d: string) => `🚨 ${d} 已進入贖回期，贖回費用較高`,
    subj_pending: (d: string) => `❌ ${d} 即將被刪除，域名進入待刪除期`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} 將在 ${n} 天後可搶註`,
    subj_dropped: (d: string) => `✅ ${d} 已釋放，現在可以註冊了`,
    subj_password_reset: (s: string) => `${s} 密碼重置請求`,
    subj_stamp_verify: (d: string) => `${d} 域名驗證超時 — 請改用檔案驗證`,

    date_locale: "zh-TW",
  } as any,

  /* ── ENGLISH ─────────────────────────────────────────────────────────── */
  en: {
    auto_sent: (siteName: string) => `This email was sent automatically by ${siteName}. Please do not reply.` as any,
    privacy: "Privacy Policy",
    terms: "Terms of Service",
    unsubscribe: "Unsubscribe",

    w_label: "Welcome",
    w_title: (n) => n ? `Hi, ${n}!` : "Welcome!",
    w_sub: "Your account has been created successfully",
    w_intro: (s) => `You now have access to all features of ${s}:`,
    w_features: FEATURES_EN,
    w_login_label: "Registered email:",
    w_cta: "Start Searching",

    sc_label: "Subscription Confirmed",
    sc_sub: "We will send you email alerts before your domain expires",
    sc_restricted_label: "Domain Status Alert Subscription",
    sc_restricted_sub: "You will be notified when this domain's status changes",
    sc_current_status: "Current Status",
    sc_subscribed: "Active Alerts",
    sc_subscribed_desc: "Automatic notification when the registration status of this domain changes",
    sc_expiry_date: "Expiry Date",
    sc_reminder_nodes: "Reminder Thresholds",
    sc_phase_alerts: "Lifecycle Phase Alerts",
    sc_grace_pill: "Grace Period entry",
    sc_redemption_pill: "Redemption Period entry",
    sc_pending_pill: "Pending Delete entry",
    sc_view_domain: "View Domain",
    sc_phases: {
      active:        { label: "Active",          desc: "Domain is valid. Reminders will be sent before expiry." },
      grace:         { label: "Grace Period",     desc: "Domain has expired but can still be renewed at normal price." },
      redemption:    { label: "Redemption",       desc: "Higher renewal cost — contact your registrar immediately." },
      pendingDelete: { label: "Pending Delete",   desc: "Domain is about to be deleted and typically cannot be renewed." },
      dropped:       { label: "Dropped",          desc: "Domain has been deleted and will soon be available to register." },
    },
    sc_prohibited_label: "Registration Prohibited",
    sc_reserved_label: "Reserved Domain",
    sc_restricted_prohibited_desc: "This domain is flagged as prohibited by the registry and generally cannot be registered through normal channels. You will be notified if its status changes.",
    sc_restricted_reserved_desc: "This domain is currently reserved by the registry and not open to public registration. You will be notified if it becomes available.",

    r_urgent_label: "⚠ Urgent Alert",
    r_label: "Expiry Reminder",
    r_sub: (n) => `Your domain expires in ${n} day${n === 1 ? "" : "s"}`,
    r_expiry_date: "Expiry Date",
    r_reg_date: "Registration Date",
    r_registrar: "Registrar",
    r_nameservers: "Name Servers",
    r_urgent_body: (n) => `Your domain expires in <strong>${n} day${n === 1 ? "" : "s"}</strong>. Renew immediately to avoid entering the grace period and incurring extra costs.`,
    r_normal_body: "Please renew your domain soon to prevent service interruption. You can ignore this reminder once renewed.",
    r_cta: "View Now",

    pe_sub: "Domain Lifecycle Status Change Notification",
    pe_orig_expiry: "Original Expiry Date",
    pe_current_status: "Current Status",
    pe_grace_label: "Grace Period Alert",
    pe_grace_badge: "Grace Period",
    pe_grace_body: "Your domain has expired but is in the grace period, allowing renewal at normal price. Contact your registrar soon to avoid entering the redemption period.",
    pe_grace_urgency: "⚠ Renew as soon as possible",
    pe_grace_next_label: "Grace Period Ends",
    pe_redemption_label: "Redemption Period Alert",
    pe_redemption_badge: "Redemption Period",
    pe_redemption_body: "The grace period has ended. Your domain is now in the redemption period where renewal typically costs 5–10× the normal price. Contact your registrar immediately.",
    pe_redemption_urgency: "🚨 High redemption fee — act now",
    pe_redemption_next_label: "Redemption Period Ends",
    pe_pending_label: "Pending Delete Alert",
    pe_pending_badge: "Pending Delete",
    pe_pending_body: "Your domain has entered the pending delete phase and can generally no longer be renewed or redeemed. It will soon be released back to the public.",
    pe_pending_urgency: "❌ Renewal is no longer possible",
    pe_pending_next_label: "Estimated Release Date",
    pe_reg_date: "Registration Date",
    pe_registrar: "Registrar",
    pe_cta: "View Domain Details",

    da_label: "Domain Drop Approaching",
    da_sub: "This domain will soon be available to register",
    da_orig_expiry: "Original Expiry Date",
    da_avail_date: "Estimated Available Date",
    da_body: "This domain has completed all hold periods and will soon be released by the registry. If you wish to register it, watch major registrar drop-catch services — it can be registered within hours to days after release.",
    da_urgency_1: "🔴 Available for registration tomorrow",
    da_urgency_n: (n) => `⚡ Available to register in ${n} day${n === 1 ? "" : "s"}`,
    da_cta: "View Domain Details",

    dd_label: "Domain Now Available",
    dd_sub: "This domain is open for registration",
    dd_orig_expiry: "Original Expiry Date",
    dd_available: "✅ This domain has completed all hold periods and is now open for public registration.",
    dd_note: "Check with your preferred registrar to register it. Some domains go to auction (DropCatch, NameJet) after release.",
    dd_cta: "View Domain Details",

    pr_label: "Account Security",
    pr_title: "Reset Your Password",
    pr_body: "We received a request to reset your password. Click the button below to set a new password. The link is valid for <strong>60 minutes</strong>.",
    pr_cta: "Reset Password",
    pr_link_note: "If the button doesn't work, copy this link into your browser:",
    pr_security: "If you didn't request this, you can safely ignore this email — your account is not at risk.",

    sv_label: "Domain Verification Timed Out",
    sv_sub: "DNS verification was not completed within the time limit",
    sv_intro: "Your domain DNS verification has timed out. Please use <strong>file verification</strong> to complete your brand claim.",
    sv_step1_title: "Step 1 — Create the verification file",
    sv_step1_body: "Create the following file path at your domain's web root:",
    sv_step2_title: "Step 2 — File content (one line)",
    sv_step3_title: "Step 3 — Trigger verification",
    sv_step3_body: "Once the file is deployed, click the button below to verify.",
    sv_cta: "Trigger File Verification",
    sv_retry: "This alert will close automatically once verified",

    subj_welcome: (s: string) => `Welcome to ${s}!`,
    subj_sub_confirm: (d: string) => `✅ Reminder set for ${d}`,
    subj_sub_restricted: (d: string) => `✅ Status alert set for ${d}`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 URGENT: ${d} expires in ${n} day${n === 1 ? "" : "s"}`,
    subj_reminder_warn: (d: string, n: number) => `🟠 ${d} expires in ${n} days`,
    subj_reminder: (d: string, n: number) => `📅 ${d} expires in ${n} days`,
    subj_grace: (d: string) => `⏰ ${d} — Grace period entered`,
    subj_redemption: (d: string) => `🚨 ${d} — Redemption period (high cost)`,
    subj_pending: (d: string) => `❌ ${d} — Pending delete`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} — Drops in ${n} day${n === 1 ? "" : "s"}`,
    subj_dropped: (d: string) => `✅ ${d} — Now available to register`,
    subj_password_reset: (s: string) => `Reset your ${s} password`,
    subj_stamp_verify: (d: string) => `${d} — DNS timeout, use file verification`,

    date_locale: "en-US",
  } as any,

  /* ── GERMAN ──────────────────────────────────────────────────────────── */
  de: {
    auto_sent: (s: string) => `Diese E-Mail wurde automatisch von ${s} gesendet. Bitte nicht antworten.` as any,
    privacy: "Datenschutz", terms: "Nutzungsbedingungen", unsubscribe: "Abmelden",
    w_label: "Willkommen", w_title: (n) => n ? `Hallo, ${n}!` : "Hallo!",
    w_sub: "Ihr Konto wurde erfolgreich erstellt",
    w_intro: (s) => `Sie haben jetzt Zugriff auf alle Funktionen von ${s}:`,
    w_features: FEATURES_DE, w_login_label: "Registrierte E-Mail:", w_cta: "Suche starten",
    sc_label: "Abo bestätigt", sc_sub: "Wir erinnern Sie per E-Mail vor dem Ablauf",
    sc_restricted_label: "Domain-Status-Abo", sc_restricted_sub: "Sie werden benachrichtigt, wenn sich der Status dieser Domain ändert",
    sc_current_status: "Aktueller Status", sc_subscribed: "Aktive Benachrichtigungen",
    sc_subscribed_desc: "Automatische Benachrichtigung bei Statusänderungen",
    sc_expiry_date: "Ablaufdatum", sc_reminder_nodes: "Erinnerungsschwellen",
    sc_phase_alerts: "Lebenszyklus-Benachrichtigungen",
    sc_grace_pill: "Karenzzeit beginnt", sc_redemption_pill: "Rückholphase beginnt", sc_pending_pill: "Löschphase beginnt",
    sc_view_domain: "Domain anzeigen",
    sc_phases: {
      active: { label: "Aktiv", desc: "Domain ist gültig. Erinnerungen werden vor Ablauf gesendet." },
      grace: { label: "Karenzzeit", desc: "Domain abgelaufen, Verlängerung zum Normalpreis möglich." },
      redemption: { label: "Rückholphase", desc: "Höhere Verlängerungskosten — sofort Registrar kontaktieren." },
      pendingDelete: { label: "Löschung ausstehend", desc: "Domain wird bald gelöscht und kann nicht mehr verlängert werden." },
      dropped: { label: "Gelöscht", desc: "Domain wurde gelöscht und ist bald wieder registrierbar." },
    },
    sc_prohibited_label: "Registrierung verboten", sc_reserved_label: "Reservierte Domain",
    sc_restricted_prohibited_desc: "Diese Domain ist vom Registry als verboten markiert und kann nicht registriert werden.",
    sc_restricted_reserved_desc: "Diese Domain ist reserviert und nicht öffentlich verfügbar. Sie werden bei Statusänderungen benachrichtigt.",
    r_urgent_label: "⚠ Dringend", r_label: "Ablauferinnerung",
    r_sub: (n) => `Ihre Domain läuft in ${n} Tag${n === 1 ? "" : "en"} ab`,
    r_expiry_date: "Ablaufdatum", r_reg_date: "Registrierungsdatum", r_registrar: "Registrar", r_nameservers: "Nameserver",
    r_urgent_body: (n) => `Ihre Domain läuft in <strong>${n} Tag${n === 1 ? "" : "en"}</strong> ab. Verlängern Sie sofort.`,
    r_normal_body: "Bitte verlängern Sie Ihre Domain, um Unterbrechungen zu vermeiden.",
    r_cta: "Jetzt ansehen",
    pe_sub: "Lebenszyklus-Statusänderung", pe_orig_expiry: "Ursprüngliches Ablaufdatum",
    pe_current_status: "Aktueller Status",
    pe_grace_label: "Karenzzeit-Benachrichtigung", pe_grace_badge: "Karenzzeit",
    pe_grace_body: "Domain abgelaufen, Verlängerung zum Normalpreis möglich. Registrar sofort kontaktieren.",
    pe_grace_urgency: "⚠ Bitte sofort verlängern", pe_grace_next_label: "Karenzzeit endet",
    pe_redemption_label: "Rückholphase", pe_redemption_badge: "Rückholphase",
    pe_redemption_body: "Verlängerungskosten 5–10× normal. Sofort Registrar kontaktieren.",
    pe_redemption_urgency: "🚨 Hohe Kosten — sofort handeln", pe_redemption_next_label: "Rückholphase endet",
    pe_pending_label: "Löschung ausstehend", pe_pending_badge: "Löschung ausstehend",
    pe_pending_body: "Domain steht vor der Löschung und kann nicht mehr verlängert werden.",
    pe_pending_urgency: "❌ Verlängerung nicht mehr möglich", pe_pending_next_label: "Erwartetes Freigabedatum",
    pe_reg_date: "Registrierungsdatum", pe_registrar: "Registrar", pe_cta: "Domain-Details anzeigen",
    da_label: "Domain-Drop bevorsteht", da_sub: "Diese Domain wird bald registrierbar",
    da_orig_expiry: "Ursprüngliches Ablaufdatum", da_avail_date: "Voraussichtliches Verfügbarkeitsdatum",
    da_body: "Die Domain hat alle Haltefristen abgeschlossen und wird bald freigegeben.",
    da_urgency_1: "🔴 Morgen registrierbar", da_urgency_n: (n) => `⚡ In ${n} Tag${n === 1 ? "" : "en"} registrierbar`,
    da_cta: "Domain-Details anzeigen",
    dd_label: "Domain jetzt verfügbar", dd_sub: "Diese Domain ist zur Registrierung geöffnet",
    dd_orig_expiry: "Ursprüngliches Ablaufdatum",
    dd_available: "✅ Domain für die Öffentlichkeit freigegeben.",
    dd_note: "Prüfen Sie bei Ihrem Registrar, ob die Registrierung möglich ist.",
    dd_cta: "Domain-Details anzeigen",
    pr_label: "Kontosicherheit", pr_title: "Passwort zurücksetzen",
    pr_body: "Wir haben eine Anfrage zum Zurücksetzen Ihres Passworts erhalten. Der Link ist <strong>60 Minuten</strong> gültig.",
    pr_cta: "Passwort zurücksetzen", pr_link_note: "Falls der Button nicht funktioniert, kopieren Sie diesen Link:",
    pr_security: "Falls Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.",
    sv_label: "Domain-Verifizierung abgelaufen", sv_sub: "DNS-Verifizierung nicht abgeschlossen",
    sv_intro: "Ihre DNS-Verifizierung ist abgelaufen. Bitte verwenden Sie die <strong>Datei-Verifizierung</strong>.",
    sv_step1_title: "Schritt 1 — Verifizierungsdatei erstellen", sv_step1_body: "Erstellen Sie diesen Dateipfad im Web-Root:",
    sv_step2_title: "Schritt 2 — Dateiinhalt (eine Zeile)",
    sv_step3_title: "Schritt 3 — Verifizierung auslösen", sv_step3_body: "Klicken Sie nach dem Hochladen den Button unten.",
    sv_cta: "Datei-Verifizierung starten", sv_retry: "Diese Benachrichtigung schließt sich automatisch nach Verifizierung",
    subj_welcome: (s: string) => `Willkommen bei ${s}!`,
    subj_sub_confirm: (d: string) => `✅ Erinnerung gesetzt für ${d}`,
    subj_sub_restricted: (d: string) => `✅ Statusbenachrichtigung für ${d}`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 DRINGEND: ${d} läuft in ${n} Tag${n === 1 ? "" : "en"} ab`,
    subj_reminder_warn: (d: string, n: number) => `🟠 ${d} läuft in ${n} Tagen ab`,
    subj_reminder: (d: string, n: number) => `📅 ${d} läuft in ${n} Tagen ab`,
    subj_grace: (d: string) => `⏰ ${d} — Karenzzeit begonnen`,
    subj_redemption: (d: string) => `🚨 ${d} — Rückholphase (hohe Kosten)`,
    subj_pending: (d: string) => `❌ ${d} — Löschung ausstehend`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} — Freigabe in ${n} Tag${n === 1 ? "" : "en"}`,
    subj_dropped: (d: string) => `✅ ${d} — Jetzt registrierbar`,
    subj_password_reset: (s: string) => `Passwort zurücksetzen bei ${s}`,
    subj_stamp_verify: (d: string) => `${d} — DNS-Timeout, Datei-Verifizierung verwenden`,

    date_locale: "de-DE",
  } as any,

  /* ── RUSSIAN ─────────────────────────────────────────────────────────── */
  ru: {
    auto_sent: (s: string) => `Это автоматическое сообщение от ${s}. Пожалуйста, не отвечайте.` as any,
    privacy: "Политика конфиденциальности", terms: "Условия использования", unsubscribe: "Отписаться",
    w_label: "Добро пожаловать", w_title: (n) => n ? `Здравствуйте, ${n}!` : "Здравствуйте!",
    w_sub: "Ваш аккаунт успешно создан",
    w_intro: (s) => `Вам доступны все функции ${s}:`,
    w_features: FEATURES_RU, w_login_label: "Email для входа:", w_cta: "Начать поиск",
    sc_label: "Подписка подтверждена", sc_sub: "Мы напомним вам по email до истечения домена",
    sc_restricted_label: "Подписка на изменение статуса", sc_restricted_sub: "Вы получите уведомление при изменении статуса домена",
    sc_current_status: "Текущий статус", sc_subscribed: "Активные уведомления",
    sc_subscribed_desc: "Автоматическое уведомление при изменении статуса регистрации",
    sc_expiry_date: "Дата истечения", sc_reminder_nodes: "Пороги напоминаний",
    sc_phase_alerts: "Уведомления о фазах жизненного цикла",
    sc_grace_pill: "Начало льготного периода", sc_redemption_pill: "Начало периода выкупа", sc_pending_pill: "Ожидание удаления",
    sc_view_domain: "Посмотреть домен",
    sc_phases: {
      active: { label: "Активен", desc: "Домен действителен. Напоминания будут отправлены до истечения." },
      grace: { label: "Льготный период", desc: "Домен истёк, но может быть продлён по обычной цене." },
      redemption: { label: "Период выкупа", desc: "Стоимость продления выше — немедленно свяжитесь с регистратором." },
      pendingDelete: { label: "Ожидание удаления", desc: "Домен вот-вот будет удалён и обычно не может быть продлён." },
      dropped: { label: "Удалён", desc: "Домен удалён и скоро станет доступен для регистрации." },
    },
    sc_prohibited_label: "Регистрация запрещена", sc_reserved_label: "Зарезервированный домен",
    sc_restricted_prohibited_desc: "Этот домен помечен реестром как запрещённый для регистрации.",
    sc_restricted_reserved_desc: "Этот домен зарезервирован реестром и недоступен для публичной регистрации.",
    r_urgent_label: "⚠ Срочно", r_label: "Напоминание об истечении",
    r_sub: (n) => `Ваш домен истекает через ${n} ${n === 1 ? "день" : n < 5 ? "дня" : "дней"}`,
    r_expiry_date: "Дата истечения", r_reg_date: "Дата регистрации", r_registrar: "Регистратор", r_nameservers: "Серверы имён",
    r_urgent_body: (n) => `Ваш домен истекает через <strong>${n} ${n === 1 ? "день" : "дней"}</strong>. Продлите немедленно.`,
    r_normal_body: "Пожалуйста, продлите домен, чтобы избежать перебоев в работе.",
    r_cta: "Посмотреть сейчас",
    pe_sub: "Уведомление об изменении статуса домена", pe_orig_expiry: "Исходная дата истечения",
    pe_current_status: "Текущий статус",
    pe_grace_label: "Уведомление о льготном периоде", pe_grace_badge: "Льготный период",
    pe_grace_body: "Домен истёк, но продление возможно по обычной цене. Свяжитесь с регистратором как можно скорее.",
    pe_grace_urgency: "⚠ Продлите как можно скорее", pe_grace_next_label: "Конец льготного периода",
    pe_redemption_label: "Период выкупа", pe_redemption_badge: "Период выкупа",
    pe_redemption_body: "Стоимость продления в 5–10 раз выше обычной. Немедленно свяжитесь с регистратором.",
    pe_redemption_urgency: "🚨 Высокая стоимость — действуйте сейчас", pe_redemption_next_label: "Конец периода выкупа",
    pe_pending_label: "Ожидание удаления", pe_pending_badge: "Ожидание удаления",
    pe_pending_body: "Домен ожидает удаления и, как правило, не может быть продлён.",
    pe_pending_urgency: "❌ Продление уже невозможно", pe_pending_next_label: "Ожидаемая дата освобождения",
    pe_reg_date: "Дата регистрации", pe_registrar: "Регистратор", pe_cta: "Подробности домена",
    da_label: "Домен скоро освободится", da_sub: "Этот домен скоро будет доступен для регистрации",
    da_orig_expiry: "Исходная дата истечения", da_avail_date: "Ожидаемая дата освобождения",
    da_body: "Домен завершил все периоды удержания и скоро будет освобождён реестром.",
    da_urgency_1: "🔴 Доступен для регистрации завтра", da_urgency_n: (n) => `⚡ Доступен через ${n} дней`,
    da_cta: "Подробности домена",
    dd_label: "Домен теперь доступен", dd_sub: "Домен открыт для регистрации",
    dd_orig_expiry: "Исходная дата истечения",
    dd_available: "✅ Домен доступен для публичной регистрации.",
    dd_note: "Проверьте у своего регистратора возможность регистрации.",
    dd_cta: "Подробности домена",
    pr_label: "Безопасность аккаунта", pr_title: "Сброс пароля",
    pr_body: "Мы получили запрос на сброс вашего пароля. Ссылка действительна <strong>60 минут</strong>.",
    pr_cta: "Сбросить пароль", pr_link_note: "Если кнопка не работает, скопируйте эту ссылку в браузер:",
    pr_security: "Если вы не запрашивали сброс, проигнорируйте это письмо.",
    sv_label: "Время верификации домена истекло", sv_sub: "DNS-верификация не завершена",
    sv_intro: "Срок DNS-верификации истёк. Используйте <strong>верификацию через файл</strong>.",
    sv_step1_title: "Шаг 1 — Создайте файл верификации", sv_step1_body: "Создайте этот файл в корне веб-сайта:",
    sv_step2_title: "Шаг 2 — Содержимое файла (одна строка)",
    sv_step3_title: "Шаг 3 — Запустите верификацию", sv_step3_body: "После загрузки файла нажмите кнопку ниже.",
    sv_cta: "Запустить верификацию", sv_retry: "Это уведомление закроется автоматически после верификации",
    subj_welcome: (s: string) => `Добро пожаловать в ${s}!`,
    subj_sub_confirm: (d: string) => `✅ Напоминание установлено для ${d}`,
    subj_sub_restricted: (d: string) => `✅ Уведомление о статусе для ${d}`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 СРОЧНО: ${d} истекает через ${n} дней`,
    subj_reminder_warn: (d: string, n: number) => `🟠 ${d} истекает через ${n} дней`,
    subj_reminder: (d: string, n: number) => `📅 ${d} истекает через ${n} дней`,
    subj_grace: (d: string) => `⏰ ${d} — Льготный период начался`,
    subj_redemption: (d: string) => `🚨 ${d} — Период выкупа (высокая стоимость)`,
    subj_pending: (d: string) => `❌ ${d} — Ожидание удаления`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} — Освобождение через ${n} дней`,
    subj_dropped: (d: string) => `✅ ${d} — Теперь доступен для регистрации`,
    subj_password_reset: (s: string) => `Сброс пароля ${s}`,
    subj_stamp_verify: (d: string) => `${d} — Тайм-аут DNS, используйте верификацию через файл`,

    date_locale: "ru-RU",
  } as any,

  /* ── JAPANESE ────────────────────────────────────────────────────────── */
  ja: {
    auto_sent: (s: string) => `このメールは${s}が自動送信しました。返信しないでください。` as any,
    privacy: "プライバシーポリシー", terms: "利用規約", unsubscribe: "配信停止",
    w_label: "ようこそ", w_title: (n) => n ? `こんにちは、${n}さん！` : "ようこそ！",
    w_sub: "アカウントが正常に作成されました",
    w_intro: (s) => `${s}のすべての機能をご利用いただけます：`,
    w_features: FEATURES_JA, w_login_label: "登録メールアドレス：", w_cta: "検索を始める",
    sc_label: "サブスクリプション確認", sc_sub: "ドメインの有効期限前にメールでお知らせします",
    sc_restricted_label: "ドメインステータス通知", sc_restricted_sub: "ドメインのステータスが変化した際に通知します",
    sc_current_status: "現在のステータス", sc_subscribed: "有効な通知",
    sc_subscribed_desc: "登録ステータスの変更時に自動通知",
    sc_expiry_date: "有効期限", sc_reminder_nodes: "通知閾値",
    sc_phase_alerts: "ライフサイクル段階通知",
    sc_grace_pill: "猶予期間の開始", sc_redemption_pill: "償還期間の開始", sc_pending_pill: "削除待ちの開始",
    sc_view_domain: "ドメインを見る",
    sc_phases: {
      active: { label: "有効", desc: "ドメインは有効です。期限前に通知します。" },
      grace: { label: "猶予期間", desc: "期限切れですが、通常価格で更新可能です。" },
      redemption: { label: "償還期間", desc: "更新費用が高くなります — すぐにレジストラに連絡してください。" },
      pendingDelete: { label: "削除待ち", desc: "まもなく削除されます。通常、更新はできません。" },
      dropped: { label: "削除済み", desc: "削除され、まもなく登録可能になります。" },
    },
    sc_prohibited_label: "登録禁止", sc_reserved_label: "予約済みドメイン",
    sc_restricted_prohibited_desc: "このドメインはレジストリにより登録禁止とされています。",
    sc_restricted_reserved_desc: "このドメインは予約済みで、一般登録は受け付けていません。",
    r_urgent_label: "⚠ 緊急通知", r_label: "有効期限リマインダー",
    r_sub: (n) => `ドメインの有効期限まで${n}日`,
    r_expiry_date: "有効期限", r_reg_date: "登録日", r_registrar: "レジストラ", r_nameservers: "ネームサーバー",
    r_urgent_body: (n) => `ドメインの有効期限まで<strong>${n}日</strong>。猶予期間に入らないよう、すぐに更新してください。`,
    r_normal_body: "サービスの中断を避けるために、早めにドメインを更新してください。",
    r_cta: "今すぐ確認",
    pe_sub: "ドメインライフサイクル変更通知", pe_orig_expiry: "元の有効期限",
    pe_current_status: "現在のステータス",
    pe_grace_label: "猶予期間通知", pe_grace_badge: "猶予期間",
    pe_grace_body: "ドメインは期限切れですが、通常価格で更新できます。すぐにレジストラに連絡してください。",
    pe_grace_urgency: "⚠ できるだけ早く更新してください", pe_grace_next_label: "猶予期間終了",
    pe_redemption_label: "償還期間通知", pe_redemption_badge: "償還期間",
    pe_redemption_body: "更新費用が通常の5〜10倍になります。すぐにレジストラに連絡してください。",
    pe_redemption_urgency: "🚨 高額な費用 — 今すぐ行動してください", pe_redemption_next_label: "償還期間終了",
    pe_pending_label: "削除待ち通知", pe_pending_badge: "削除待ち",
    pe_pending_body: "ドメインは削除待ち状態で、通常は更新できません。",
    pe_pending_urgency: "❌ 更新はできません", pe_pending_next_label: "予想リリース日",
    pe_reg_date: "登録日", pe_registrar: "レジストラ", pe_cta: "ドメイン詳細を見る",
    da_label: "ドメインが間もなく登録可能", da_sub: "このドメインは間もなく登録可能になります",
    da_orig_expiry: "元の有効期限", da_avail_date: "予想登録可能日",
    da_body: "ドメインはすべての保留期間を完了し、まもなくリリースされます。",
    da_urgency_1: "🔴 明日から登録可能", da_urgency_n: (n) => `⚡ ${n}日後に登録可能`,
    da_cta: "ドメイン詳細を見る",
    dd_label: "ドメインが利用可能になりました", dd_sub: "このドメインは登録可能です",
    dd_orig_expiry: "元の有効期限",
    dd_available: "✅ ドメインは一般登録に開放されました。",
    dd_note: "レジストラでの登録可否をご確認ください。",
    dd_cta: "ドメイン詳細を見る",
    pr_label: "アカウントセキュリティ", pr_title: "パスワードをリセット",
    pr_body: "パスワードリセットのリクエストを受け付けました。リンクは<strong>60分間</strong>有効です。",
    pr_cta: "パスワードをリセット", pr_link_note: "ボタンが機能しない場合は、このリンクをブラウザにコピーしてください：",
    pr_security: "リセットを要求していない場合は、このメールを無視してください。",
    sv_label: "ドメイン検証タイムアウト", sv_sub: "DNS検証が時間内に完了しませんでした",
    sv_intro: "DNS検証がタイムアウトしました。<strong>ファイル検証</strong>を使用してください。",
    sv_step1_title: "ステップ1 — 検証ファイルの作成", sv_step1_body: "ウェブルートに次のファイルパスを作成してください：",
    sv_step2_title: "ステップ2 — ファイルの内容（1行）",
    sv_step3_title: "ステップ3 — 検証を実行", sv_step3_body: "ファイルをアップロードしたら、下のボタンをクリックしてください。",
    sv_cta: "ファイル検証を実行", sv_retry: "検証後、この通知は自動的に閉じます",
    subj_welcome: (s: string) => `${s}へようこそ！`,
    subj_sub_confirm: (d: string) => `✅ ${d} のリマインダーを設定しました`,
    subj_sub_restricted: (d: string) => `✅ ${d} のステータスアラートを設定しました`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 緊急: ${d} が${n}日後に期限切れ`,
    subj_reminder_warn: (d: string, n: number) => `🟠 ${d} が${n}日後に期限切れ`,
    subj_reminder: (d: string, n: number) => `📅 ${d} が${n}日後に期限切れ`,
    subj_grace: (d: string) => `⏰ ${d} — 猶予期間が始まりました`,
    subj_redemption: (d: string) => `🚨 ${d} — 償還期間（高額費用）`,
    subj_pending: (d: string) => `❌ ${d} — 削除待ち`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} — ${n}日後にドロップ`,
    subj_dropped: (d: string) => `✅ ${d} — 登録可能になりました`,
    subj_password_reset: (s: string) => `${s} パスワードリセット`,
    subj_stamp_verify: (d: string) => `${d} — DNSタイムアウト、ファイル検証をご利用ください`,

    date_locale: "ja-JP",
  } as any,

  /* ── FRENCH ──────────────────────────────────────────────────────────── */
  fr: {
    auto_sent: (s: string) => `Cet e-mail a été envoyé automatiquement par ${s}. Merci de ne pas répondre.` as any,
    privacy: "Politique de confidentialité", terms: "Conditions d'utilisation", unsubscribe: "Se désabonner",
    w_label: "Bienvenue", w_title: (n) => n ? `Bonjour, ${n} !` : "Bienvenue !",
    w_sub: "Votre compte a été créé avec succès",
    w_intro: (s) => `Vous avez accès à toutes les fonctionnalités de ${s} :`,
    w_features: FEATURES_FR, w_login_label: "E-mail enregistré :", w_cta: "Commencer la recherche",
    sc_label: "Abonnement confirmé", sc_sub: "Nous vous rappellerons avant l'expiration de votre domaine",
    sc_restricted_label: "Abonnement aux alertes de statut", sc_restricted_sub: "Vous serez notifié lors des changements de statut",
    sc_current_status: "Statut actuel", sc_subscribed: "Alertes actives",
    sc_subscribed_desc: "Notification automatique lors des changements de statut d'enregistrement",
    sc_expiry_date: "Date d'expiration", sc_reminder_nodes: "Seuils de rappel",
    sc_phase_alerts: "Alertes de phase du cycle de vie",
    sc_grace_pill: "Début de la période de grâce", sc_redemption_pill: "Début de la rédemption", sc_pending_pill: "Suppression en attente",
    sc_view_domain: "Voir le domaine",
    sc_phases: {
      active: { label: "Actif", desc: "Le domaine est valide. Des rappels seront envoyés avant expiration." },
      grace: { label: "Période de grâce", desc: "Le domaine a expiré mais peut encore être renouvelé au prix normal." },
      redemption: { label: "Rédemption", desc: "Coût de renouvellement élevé — contactez votre registrar immédiatement." },
      pendingDelete: { label: "Suppression en attente", desc: "Le domaine va bientôt être supprimé et ne peut généralement plus être renouvelé." },
      dropped: { label: "Supprimé", desc: "Le domaine a été supprimé et sera bientôt disponible." },
    },
    sc_prohibited_label: "Enregistrement interdit", sc_reserved_label: "Domaine réservé",
    sc_restricted_prohibited_desc: "Ce domaine est marqué comme interdit par le registre.",
    sc_restricted_reserved_desc: "Ce domaine est réservé par le registre et non disponible au public.",
    r_urgent_label: "⚠ Urgent", r_label: "Rappel d'expiration",
    r_sub: (n) => `Votre domaine expire dans ${n} jour${n > 1 ? "s" : ""}`,
    r_expiry_date: "Date d'expiration", r_reg_date: "Date d'enregistrement", r_registrar: "Bureau d'enregistrement", r_nameservers: "Serveurs de noms",
    r_urgent_body: (n) => `Votre domaine expire dans <strong>${n} jour${n > 1 ? "s" : ""}</strong>. Renouvelez-le immédiatement.`,
    r_normal_body: "Veuillez renouveler votre domaine pour éviter toute interruption de service.",
    r_cta: "Voir maintenant",
    pe_sub: "Notification de changement de statut", pe_orig_expiry: "Date d'expiration initiale",
    pe_current_status: "Statut actuel",
    pe_grace_label: "Alerte période de grâce", pe_grace_badge: "Période de grâce",
    pe_grace_body: "Le domaine a expiré mais peut encore être renouvelé. Contactez votre registrar rapidement.",
    pe_grace_urgency: "⚠ Renouvelez dès que possible", pe_grace_next_label: "Fin de la période de grâce",
    pe_redemption_label: "Alerte rédemption", pe_redemption_badge: "Rédemption",
    pe_redemption_body: "Coût de renouvellement 5–10× le prix normal. Contactez votre registrar immédiatement.",
    pe_redemption_urgency: "🚨 Coût élevé — agissez maintenant", pe_redemption_next_label: "Fin de la rédemption",
    pe_pending_label: "Suppression en attente", pe_pending_badge: "Suppression en attente",
    pe_pending_body: "Le domaine est en attente de suppression et ne peut généralement plus être renouvelé.",
    pe_pending_urgency: "❌ Renouvellement impossible", pe_pending_next_label: "Date de libération estimée",
    pe_reg_date: "Date d'enregistrement", pe_registrar: "Bureau d'enregistrement", pe_cta: "Détails du domaine",
    da_label: "Le domaine va bientôt être disponible", da_sub: "Ce domaine sera bientôt disponible à l'enregistrement",
    da_orig_expiry: "Date d'expiration initiale", da_avail_date: "Date de disponibilité estimée",
    da_body: "Ce domaine a terminé toutes les périodes de rétention et sera bientôt libéré.",
    da_urgency_1: "🔴 Disponible demain", da_urgency_n: (n) => `⚡ Disponible dans ${n} jour${n > 1 ? "s" : ""}`,
    da_cta: "Détails du domaine",
    dd_label: "Domaine maintenant disponible", dd_sub: "Ce domaine est ouvert à l'enregistrement",
    dd_orig_expiry: "Date d'expiration initiale",
    dd_available: "✅ Ce domaine est ouvert à l'enregistrement public.",
    dd_note: "Vérifiez auprès de votre registrar si vous pouvez l'enregistrer.",
    dd_cta: "Détails du domaine",
    pr_label: "Sécurité du compte", pr_title: "Réinitialiser votre mot de passe",
    pr_body: "Nous avons reçu une demande de réinitialisation de mot de passe. Le lien est valable <strong>60 minutes</strong>.",
    pr_cta: "Réinitialiser le mot de passe", pr_link_note: "Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :",
    pr_security: "Si vous n'avez pas fait cette demande, ignorez cet e-mail.",
    sv_label: "Vérification de domaine expirée", sv_sub: "La vérification DNS n'a pas été complétée",
    sv_intro: "La vérification DNS a expiré. Utilisez la <strong>vérification par fichier</strong>.",
    sv_step1_title: "Étape 1 — Créer le fichier de vérification", sv_step1_body: "Créez ce chemin de fichier à la racine web :",
    sv_step2_title: "Étape 2 — Contenu du fichier (une ligne)",
    sv_step3_title: "Étape 3 — Déclencher la vérification", sv_step3_body: "Après avoir déployé le fichier, cliquez sur le bouton ci-dessous.",
    sv_cta: "Déclencher la vérification", sv_retry: "Cette alerte se fermera automatiquement après vérification",
    subj_welcome: (s: string) => `Bienvenue sur ${s} !`,
    subj_sub_confirm: (d: string) => `✅ Rappel activé pour ${d}`,
    subj_sub_restricted: (d: string) => `✅ Alerte de statut activée pour ${d}`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 URGENT : ${d} expire dans ${n} jour${n > 1 ? "s" : ""}`,
    subj_reminder_warn: (d: string, n: number) => `🟠 ${d} expire dans ${n} jours`,
    subj_reminder: (d: string, n: number) => `📅 ${d} expire dans ${n} jours`,
    subj_grace: (d: string) => `⏰ ${d} — Période de grâce commencée`,
    subj_redemption: (d: string) => `🚨 ${d} — Rédemption (coût élevé)`,
    subj_pending: (d: string) => `❌ ${d} — Suppression en attente`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} — Libération dans ${n} jour${n > 1 ? "s" : ""}`,
    subj_dropped: (d: string) => `✅ ${d} — Disponible à l'enregistrement`,
    subj_password_reset: (s: string) => `Réinitialisation de votre mot de passe ${s}`,
    subj_stamp_verify: (d: string) => `${d} — Délai DNS dépassé, utilisez la vérification par fichier`,

    date_locale: "fr-FR",
  } as any,

  /* ── KOREAN ──────────────────────────────────────────────────────────── */
  ko: {
    auto_sent: (s: string) => `이 이메일은 ${s}에서 자동으로 발송되었습니다. 회신하지 마세요.` as any,
    privacy: "개인정보 처리방침", terms: "이용약관", unsubscribe: "수신 거부",
    w_label: "환영합니다", w_title: (n) => n ? `안녕하세요, ${n}님!` : "환영합니다!",
    w_sub: "계정이 성공적으로 생성되었습니다",
    w_intro: (s) => `${s}의 모든 기능을 이용하실 수 있습니다:`,
    w_features: FEATURES_KO, w_login_label: "등록 이메일:", w_cta: "검색 시작",
    sc_label: "구독 확인", sc_sub: "도메인 만료 전에 이메일로 알려드리겠습니다",
    sc_restricted_label: "도메인 상태 알림 구독", sc_restricted_sub: "도메인 상태가 변경되면 알려드리겠습니다",
    sc_current_status: "현재 상태", sc_subscribed: "활성 알림",
    sc_subscribed_desc: "등록 상태가 변경될 때 자동으로 알림",
    sc_expiry_date: "만료일", sc_reminder_nodes: "알림 기준일",
    sc_phase_alerts: "생애주기 단계 알림",
    sc_grace_pill: "유예 기간 시작", sc_redemption_pill: "복구 기간 시작", sc_pending_pill: "삭제 대기 시작",
    sc_view_domain: "도메인 보기",
    sc_phases: {
      active: { label: "활성", desc: "도메인이 유효합니다. 만료 전에 알림을 보내드립니다." },
      grace: { label: "유예 기간", desc: "만료되었지만 정상 가격으로 갱신 가능합니다." },
      redemption: { label: "복구 기간", desc: "갱신 비용이 높습니다 — 즉시 레지스트라에 연락하세요." },
      pendingDelete: { label: "삭제 대기", desc: "곧 삭제되며 일반적으로 갱신이 불가능합니다." },
      dropped: { label: "삭제됨", desc: "삭제되었으며 곧 등록 가능해집니다." },
    },
    sc_prohibited_label: "등록 금지", sc_reserved_label: "예약된 도메인",
    sc_restricted_prohibited_desc: "이 도메인은 레지스트리에 의해 등록 금지로 표시되어 있습니다.",
    sc_restricted_reserved_desc: "이 도메인은 레지스트리에 의해 예약되어 공개 등록이 불가능합니다.",
    r_urgent_label: "⚠ 긴급 알림", r_label: "만료 알림",
    r_sub: (n) => `도메인 만료까지 ${n}일 남았습니다`,
    r_expiry_date: "만료일", r_reg_date: "등록일", r_registrar: "레지스트라", r_nameservers: "네임서버",
    r_urgent_body: (n) => `도메인이 <strong>${n}일</strong> 후 만료됩니다. 즉시 갱신하세요.`,
    r_normal_body: "서비스 중단을 방지하려면 도메인을 빨리 갱신하세요.",
    r_cta: "지금 보기",
    pe_sub: "도메인 생애주기 상태 변경 알림", pe_orig_expiry: "원래 만료일",
    pe_current_status: "현재 상태",
    pe_grace_label: "유예 기간 알림", pe_grace_badge: "유예 기간",
    pe_grace_body: "도메인이 만료되었지만 정상 가격으로 갱신 가능합니다. 빨리 레지스트라에 연락하세요.",
    pe_grace_urgency: "⚠ 최대한 빨리 갱신하세요", pe_grace_next_label: "유예 기간 종료",
    pe_redemption_label: "복구 기간 알림", pe_redemption_badge: "복구 기간",
    pe_redemption_body: "갱신 비용이 정상 가격의 5~10배입니다. 즉시 레지스트라에 연락하세요.",
    pe_redemption_urgency: "🚨 높은 비용 — 지금 행동하세요", pe_redemption_next_label: "복구 기간 종료",
    pe_pending_label: "삭제 대기 알림", pe_pending_badge: "삭제 대기",
    pe_pending_body: "도메인이 삭제 대기 상태이며 일반적으로 갱신할 수 없습니다.",
    pe_pending_urgency: "❌ 갱신 불가", pe_pending_next_label: "예상 해제일",
    pe_reg_date: "등록일", pe_registrar: "레지스트라", pe_cta: "도메인 상세 보기",
    da_label: "도메인 드롭 임박", da_sub: "이 도메인은 곧 등록 가능해집니다",
    da_orig_expiry: "원래 만료일", da_avail_date: "예상 등록 가능일",
    da_body: "도메인이 모든 보류 기간을 완료하고 곧 레지스트리에서 해제됩니다.",
    da_urgency_1: "🔴 내일부터 등록 가능", da_urgency_n: (n) => `⚡ ${n}일 후 등록 가능`,
    da_cta: "도메인 상세 보기",
    dd_label: "도메인 이제 사용 가능", dd_sub: "이 도메인은 등록 가능합니다",
    dd_orig_expiry: "원래 만료일",
    dd_available: "✅ 이 도메인은 공개 등록에 개방되었습니다.",
    dd_note: "레지스트라에서 등록 가능 여부를 확인하세요.",
    dd_cta: "도메인 상세 보기",
    pr_label: "계정 보안", pr_title: "비밀번호 재설정",
    pr_body: "비밀번호 재설정 요청을 받았습니다. 링크는 <strong>60분</strong> 동안 유효합니다.",
    pr_cta: "비밀번호 재설정", pr_link_note: "버튼이 작동하지 않으면 이 링크를 브라우저에 복사하세요:",
    pr_security: "요청하지 않은 경우 이 이메일을 무시하세요.",
    sv_label: "도메인 인증 시간 초과", sv_sub: "DNS 인증이 제한 시간 내에 완료되지 않았습니다",
    sv_intro: "DNS 인증 시간이 초과되었습니다. <strong>파일 인증</strong>을 사용하세요.",
    sv_step1_title: "1단계 — 인증 파일 만들기", sv_step1_body: "웹 루트에 다음 파일 경로를 만드세요:",
    sv_step2_title: "2단계 — 파일 내용 (한 줄)",
    sv_step3_title: "3단계 — 인증 실행", sv_step3_body: "파일을 배포한 후 아래 버튼을 클릭하세요.",
    sv_cta: "파일 인증 실행", sv_retry: "인증 후 이 알림은 자동으로 닫힙니다",
    subj_welcome: (s: string) => `${s}에 오신 것을 환영합니다!`,
    subj_sub_confirm: (d: string) => `✅ ${d} 알림이 설정되었습니다`,
    subj_sub_restricted: (d: string) => `✅ ${d} 상태 알림이 설정되었습니다`,
    subj_reminder_urgent: (d: string, n: number) => `🔴 긴급: ${d}이(가) ${n}일 후 만료됩니다`,
    subj_reminder_warn: (d: string, n: number) => `🟠 ${d}이(가) ${n}일 후 만료됩니다`,
    subj_reminder: (d: string, n: number) => `📅 ${d}이(가) ${n}일 후 만료됩니다`,
    subj_grace: (d: string) => `⏰ ${d} — 유예 기간이 시작되었습니다`,
    subj_redemption: (d: string) => `🚨 ${d} — 복구 기간 (높은 비용)`,
    subj_pending: (d: string) => `❌ ${d} — 삭제 대기`,
    subj_drop_soon: (d: string, n: number) => `⚡ ${d} — ${n}일 후 해제`,
    subj_dropped: (d: string) => `✅ ${d} — 이제 등록 가능합니다`,
    subj_password_reset: (s: string) => `${s} 비밀번호 재설정`,
    subj_stamp_verify: (d: string) => `${d} — DNS 시간 초과, 파일 인증을 사용하세요`,

    date_locale: "ko-KR",
  } as any,
};

export function getEmailStrings(locale: string | null | undefined): EmailStrings {
  const l = normalizeEmailLocale(locale);
  return EMAIL_STRINGS[l] ?? EMAIL_STRINGS.zh;
}

/** Format a date string using the given locale's date formatting */
export function fmtEmailDate(dateStr: string | null | undefined, strings: EmailStrings): string {
  if (!dateStr) return "—";
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    return d.toLocaleDateString(strings.date_locale, { year: "numeric", month: "long", day: "numeric" });
  } catch {
    return dateStr;
  }
}
