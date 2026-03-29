/**
 * Shared email helpers — send via Resend, consistent HTML template.
 */

import { one } from "@/lib/db-query";

const PRIMARY    = "#7c3aed";   // violet-600
const PRIMARY_LT = "#8b5cf6";   // violet-500
const DARK       = "#0f172a";   // slate-900
const FONT       = "Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";
const BASE_URL   = () => process.env.NEXT_PUBLIC_BASE_URL || "https://x.rw";

// ── Server-side site label (cached, reads from DB) ───────────────────────────
let _labelCache: string | null = null;
let _labelCacheAt = 0;
const LABEL_TTL = 60_000;

export async function getSiteLabel(): Promise<string> {
  if (_labelCache && Date.now() - _labelCacheAt < LABEL_TTL) return _labelCache;
  try {
    const row = await one<{ value: string }>(
      "SELECT value FROM site_settings WHERE key = 'site_logo_text'"
    );
    _labelCache = (row?.value?.trim()) || "X.RW";
  } catch {
    _labelCache = "X.RW";
  }
  _labelCacheAt = Date.now();
  return _labelCache!;
}

// ── Shared primitives ────────────────────────────────────────────────────────

function emailLayout(body: string, siteName = "X.RW"): string {
  const year = new Date().getFullYear();
  // Split on last space to colour the final word with PRIMARY
  const parts = siteName.trim().split(" ");
  const head = parts.length > 1 ? parts.slice(0, -1).join(" ") : "";
  const tail = parts[parts.length - 1];
  const logoHtml = head
    ? `${head}&thinsp;<span style="color:${PRIMARY}">${tail}</span>`
    : `<span style="color:${PRIMARY}">${tail}</span>`;

  return `<!DOCTYPE html>
<html lang="und">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>${siteName}</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:${FONT}">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px;background:#f1f5f9">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:540px">

        <!-- Logo -->
        <tr>
          <td style="padding-bottom:20px;text-align:center">
            <a href="${BASE_URL()}" style="text-decoration:none">
              <span style="font-size:18px;font-weight:800;letter-spacing:-0.5px;color:${DARK}">${logoHtml}</span>
            </a>
          </td>
        </tr>

        <!-- Card -->
        <tr>
          <td style="background:#ffffff;border-radius:16px;border:1px solid #e2e8f0;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.07)">
            ${body}
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:24px 8px 0;text-align:center">
            <p style="margin:0 0 4px;font-size:11px;color:#94a3b8;line-height:1.9">
              此邮件由 <a href="${BASE_URL()}" style="color:${PRIMARY};text-decoration:none">${siteName}</a> 自动发送，请勿直接回复
              <span style="color:#cbd5e1;margin:0 6px">·</span>
              This is an automated message from <a href="${BASE_URL()}" style="color:${PRIMARY};text-decoration:none">${siteName}</a>, please do not reply
            </p>
            <p style="margin:0;font-size:11px;color:#cbd5e1">
              © ${year} ${siteName}
              <span style="margin:0 6px">·</span>
              <a href="${BASE_URL()}/privacy" style="color:#cbd5e1;text-decoration:none">Privacy</a>
              <span style="margin:0 6px">·</span>
              <a href="${BASE_URL()}/terms" style="color:#cbd5e1;text-decoration:none">Terms</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

/** Domain name displayed monospace */
function domainBadge(domain: string) {
  return `<span style="font-family:ui-monospace,'Fira Code',monospace;font-size:inherit;font-weight:800;letter-spacing:-0.3px">${domain}</span>`;
}

/** Coloured pill tag */
function pill(text: string, bg = "#ede9fe", color = "#5b21b6") {
  return `<span style="display:inline-block;background:${bg};color:${color};padding:3px 11px;border-radius:999px;font-size:12px;font-weight:600;margin:3px 3px 3px 0">${text}</span>`;
}

/** Key-value row inside an info block */
function kvRow(label: string, value: string, valueStyle = "") {
  return `<tr>
    <td style="padding:10px 0;font-size:12px;color:#94a3b8;font-weight:500;width:110px;vertical-align:top;border-bottom:1px solid #f1f5f9">${label}</td>
    <td style="padding:10px 0;font-size:13px;color:#1e293b;font-weight:600;border-bottom:1px solid #f1f5f9;${valueStyle}">${value}</td>
  </tr>`;
}

/** Card section with padding */
function section(html: string, pt = "28px", pr = "32px", pb = "28px", pl = "32px") {
  return `<div style="padding:${pt} ${pr} ${pb} ${pl}">${html}</div>`;
}

/** Thin divider */
function divider() {
  return `<div style="height:1px;background:#f1f5f9"></div>`;
}

/** Dark header band */
function darkHeader(label: string, title: string, sub = "") {
  return `<div style="background:${DARK};padding:28px 32px 24px;position:relative">
    <p style="margin:0;font-size:10px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,.4);text-transform:uppercase">${label}</p>
    <h1 style="margin:8px 0 ${sub ? "6px" : "0"};font-size:22px;font-weight:800;color:#fff;line-height:1.3">${title}</h1>
    ${sub ? `<p style="margin:0;font-size:13px;color:rgba(255,255,255,.55)">${sub}</p>` : ""}
    <div style="position:absolute;top:0;right:0;width:80px;height:100%;background:linear-gradient(to left,rgba(124,58,237,.18),transparent);pointer-events:none"></div>
  </div>`;
}

/** Coloured header band (for urgent/phase alerts) */
function colorHeader(bg: string, label: string, title: string, sub = "") {
  return `<div style="background:${bg};padding:28px 32px 24px">
    <p style="margin:0;font-size:10px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,.65);text-transform:uppercase">${label}</p>
    <h1 style="margin:8px 0 ${sub ? "6px" : "0"};font-size:22px;font-weight:800;color:#fff;line-height:1.3">${title}</h1>
    ${sub ? `<p style="margin:0;font-size:13px;color:rgba(255,255,255,.75)">${sub}</p>` : ""}
  </div>`;
}

/** Primary CTA button */
function ctaBtn(href: string, label: string, color = PRIMARY) {
  return `<a href="${href}" style="display:inline-block;background:${color};color:#fff;font-size:13px;font-weight:700;padding:12px 26px;border-radius:10px;text-decoration:none;letter-spacing:0.1px">${label} →</a>`;
}

/** Ghost / cancel link */
function ghostLink(href: string, label: string) {
  return `<a href="${href}" style="font-size:11px;color:#94a3b8;text-decoration:underline;text-underline-offset:3px">${label}</a>`;
}

// ── Footer action row (button + optional ghost link) ─────────────────────────
function actionRow(btnHref: string, btnLabel: string, cancelHref?: string, btnColor = PRIMARY) {
  return `<div style="padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
    ${ctaBtn(btnHref, btnLabel, btnColor)}
    ${cancelHref ? ghostLink(cancelHref, "取消订阅 · Unsubscribe") : ""}
  </div>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. Welcome email
// ──────────────────────────────────────────────────────────────────────────────
export function welcomeHtml({ name, email, siteName = "X.RW" }: { name?: string | null; email: string; siteName?: string }): string {
  const greeting = name ? `你好，${name}` : "你好";
  const features: [string, string, string][] = [
    ["🔍", "无限查询", "WHOIS / RDAP · 域名、IP、ASN、CIDR 全支持"],
    ["🔔", "到期订阅提醒", "多节点自动推送，不错过任何续费时间"],
    ["🛡️", "品牌认领", "为您拥有的域名设置认证标签"],
    ["📊", "搜索历史", "随时回顾查询记录"],
  ];

  return emailLayout(`
    ${darkHeader("欢迎加入", greeting + "！", "您的账号已成功创建")}

    ${section(`
      <p style="margin:0 0 20px;font-size:13px;color:#64748b;line-height:1.8">
        现在可以使用 ${siteName} 的全部功能：
      </p>
      <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:20px">
        ${features.map(([icon, title, desc]) => `
          <tr>
            <td style="width:40px;padding:9px 12px 9px 0;vertical-align:middle;font-size:18px;line-height:1">${icon}</td>
            <td style="padding:9px 0;border-bottom:1px solid #f8fafc">
              <p style="margin:0;font-size:13px;font-weight:700;color:#1e293b">${title}</p>
              <p style="margin:2px 0 0;font-size:12px;color:#94a3b8">${desc}</p>
            </td>
          </tr>
        `).join("")}
      </table>
      <p style="margin:0;font-size:12px;color:#94a3b8">
        登录邮箱：<span style="font-family:monospace;color:#334155;font-weight:600">${email}</span>
      </p>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}`, "开始查询")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. Subscription confirmation email
// ──────────────────────────────────────────────────────────────────────────────
export interface SubscriptionEmailParams {
  domain: string;
  expirationDate: string | null;
  cancelToken: string;
  thresholds: number[];
  regStatusType?: string;
  lifecycle?: {
    phase: string;
    graceEnd: string;
    redemptionEnd: string;
    dropDate: string;
    hasGrace?: boolean;
    hasRedemption?: boolean;
    hasPendingDelete?: boolean;
    registry?: string;
  };
}

export function subscriptionConfirmHtml(p: SubscriptionEmailParams & { siteName?: string }): string {
  const siteName = p.siteName || "X.RW";
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const isRestricted = p.regStatusType === "prohibited" || p.regStatusType === "reserved";

  // ── Restricted domain email (prohibited / reserved) ──────────────────────
  if (isRestricted) {
    const statusLabel = p.regStatusType === "prohibited" ? "禁止注册" : "保留域名";
    const statusColor = p.regStatusType === "prohibited" ? "#dc2626" : "#d97706";
    const statusBg    = p.regStatusType === "prohibited" ? "#fef2f2" : "#fffbeb";
    const statusDesc  = p.regStatusType === "prohibited"
      ? "该域名被注册局标记为禁止注册字符串，通常无法通过常规渠道注册。当域名注册状态发生变化时，我们将第一时间通知您。"
      : "该域名目前为注册局保留状态，不对公众开放注册。如域名状态变化或开放注册，我们将立即发送通知。";

    return emailLayout(`
      ${darkHeader("域名状态变化订阅", domainBadge(p.domain), "域名状态变化时，我们将第一时间通知您")}

      ${section(`
        <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:20px">
          <div style="padding:12px 18px;background:${statusBg}">
            <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:${statusColor};text-transform:uppercase">当前状态 · ${statusLabel}</p>
            <p style="margin:6px 0 0;font-size:12px;color:#475569;line-height:1.7">${statusDesc}</p>
          </div>
          <div style="padding:12px 18px;border-top:1px solid #e2e8f0;background:#f0f9ff">
            <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:#0284c7;text-transform:uppercase">已订阅的提醒</p>
            <p style="margin:6px 0 0;font-size:13px;font-weight:700;color:#0c4a6e">✓ 域名状态变化通知</p>
            <p style="margin:4px 0 0;font-size:12px;color:#64748b;line-height:1.6">当该域名的注册状态发生任何变化（如解禁、开放注册、状态转变）时自动通知。</p>
          </div>
        </div>
      `)}

      ${divider()}
      ${actionRow(`${BASE_URL()}/${p.domain}`, "查看域名", cancelUrl)}
    `, siteName);
  }

  // ── Normal domain email ───────────────────────────────────────────────────
  const expiryStr = p.expirationDate
    ? new Date(p.expirationDate).toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric" })
    : "未知";

  const phaseMap: Record<string, { label: string; color: string; bg: string; desc: string }> = {
    active:        { label: "有效期内",  color: "#059669", bg: "#ecfdf5", desc: "域名状态正常，到期前将自动发送提醒。" },
    grace:         { label: "宽限期",    color: "#d97706", bg: "#fffbeb", desc: "域名已过期，仍可按正常价格续费。" },
    redemption:    { label: "赎回期",    color: "#ea580c", bg: "#fff7ed", desc: "续费费用较高，请尽快联系注册商赎回。" },
    pendingDelete: { label: "待删除",    color: "#dc2626", bg: "#fef2f2", desc: "域名即将被注册局删除，通常无法再续费。" },
    dropped:       { label: "已删除",    color: "#6b7280", bg: "#f9fafb", desc: "域名已删除，即将重新开放注册。" },
  };
  const lc = p.lifecycle;
  const phase = phaseMap[lc?.phase ?? "active"] ?? phaseMap.active;

  return emailLayout(`
    ${darkHeader("域名订阅确认", domainBadge(p.domain), "我们将在到期前自动发送邮件提醒")}

    ${section(`
      <!-- Info block -->
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:20px">
        <div style="padding:14px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">过期日期</p>
          <p style="margin:6px 0 0;font-size:20px;font-weight:800;color:#1e293b;font-family:ui-monospace,'Fira Code',monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:${phase.bg}">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:${phase.color};text-transform:uppercase">当前状态 · ${phase.label}</p>
          <p style="margin:6px 0 0;font-size:12px;color:#475569;line-height:1.7">${phase.desc}</p>
        </div>
      </div>

      <!-- Thresholds -->
      <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#1e293b">提醒节点</p>
      <div style="margin-bottom:${lc && (lc.hasGrace || lc.hasRedemption || lc.hasPendingDelete) ? "16px" : "0"}">
        ${p.thresholds.map(d => pill(`提前 ${d} 天`)).join("")}
      </div>
      ${lc && (lc.hasGrace || lc.hasRedemption || lc.hasPendingDelete) ? `
      <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#1e293b">生命周期阶段提醒</p>
      <div>
        ${lc.hasGrace      ? pill("进入宽限期", "#fffbeb", "#d97706") : ""}
        ${lc.hasRedemption ? pill("进入赎回期", "#fff7ed", "#ea580c") : ""}
        ${lc.hasPendingDelete ? pill("进入待删除期", "#fef2f2", "#dc2626") : ""}
      </div>` : ""}
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, "查看域名", cancelUrl)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Expiry reminder email
// ──────────────────────────────────────────────────────────────────────────────
export function reminderHtml({
  domain, expirationDate, daysLeft, cancelToken, siteName = "X.RW",
}: { domain: string; expirationDate: string | null; daysLeft: number; cancelToken: string; siteName?: string }): string {
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${cancelToken}`;
  const expiryStr = expirationDate
    ? new Date(expirationDate).toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric" })
    : "即将到期";

  const urgent = daysLeft <= 5;
  const warn   = daysLeft <= 15;
  const hdrBg  = urgent ? "#dc2626" : warn ? "#d97706" : DARK;
  const hdrLabel = urgent ? "⚠ 紧急提醒" : "到期提醒";
  const btnColor = urgent ? "#dc2626" : warn ? "#d97706" : PRIMARY;

  const bodyText = urgent
    ? `域名将在 <strong>${daysLeft} 天</strong>内过期，请立即前往注册商续费，避免进入宽限期产生额外费用。`
    : `请尽快续费您的域名，以免服务因过期而中断。续费成功后可忽略此提醒。`;

  return emailLayout(`
    ${urgent || warn
      ? colorHeader(hdrBg, hdrLabel, domainBadge(domain), `距离到期还有 ${daysLeft} 天`)
      : darkHeader(hdrLabel, domainBadge(domain), `距离到期还有 ${daysLeft} 天`)}

    ${section(`
      <div style="border:1px solid #e2e8f0;border-radius:12px;padding:16px 18px;margin-bottom:18px">
        <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">过期日期</p>
        <p style="margin:6px 0 0;font-size:22px;font-weight:800;color:#1e293b;font-family:ui-monospace,'Fira Code',monospace">${expiryStr}</p>
      </div>
      <p style="margin:0;font-size:13px;color:#475569;line-height:1.8">${bodyText}</p>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${domain}`, "立即查看", cancelUrl, btnColor)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. Phase event email (grace / redemption / pending-delete entered)
// ──────────────────────────────────────────────────────────────────────────────
export interface PhaseEventEmailParams {
  domain: string;
  phase: "grace" | "redemption" | "pendingDelete";
  expirationDate: string | null;
  graceEnd?: string;
  redemptionEnd?: string;
  dropDate?: string;
  cancelToken: string;
}

export function phaseEventHtml(p: PhaseEventEmailParams & { siteName?: string }): string {
  const siteName = p.siteName || "X.RW";
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = p.expirationDate
    ? new Date(p.expirationDate).toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric" })
    : "未知";

  const cfg = {
    grace: {
      bg: "#d97706", label: "宽限期提醒",
      badge: "宽限期",  badgeColor: "#d97706", badgeBg: "#fffbeb",
      body: "域名已过期但仍处于宽限期，可按正常价格续费。请尽快联系注册商，以免进入赎回期产生额外费用。",
      urgency: "⚠ 请尽快续费", urgencyColor: "#92400e", urgencyBg: "#fffbeb",
      nextLabel: "宽限期结束", nextDate: p.graceEnd, nextColor: "#d97706",
    },
    redemption: {
      bg: "#ea580c", label: "赎回期提醒",
      badge: "赎回期",  badgeColor: "#ea580c", badgeBg: "#fff7ed",
      body: "宽限期已结束，域名进入赎回期。赎回费用通常为正常价格的 5–10 倍，请立即联系注册商申请赎回。",
      urgency: "🚨 高额赎回费，请立即操作", urgencyColor: "#9a3412", urgencyBg: "#fff7ed",
      nextLabel: "赎回期结束", nextDate: p.redemptionEnd, nextColor: "#ea580c",
    },
    pendingDelete: {
      bg: "#dc2626", label: "待删除提醒",
      badge: "待删除",  badgeColor: "#dc2626", badgeBg: "#fef2f2",
      body: "域名已进入待删除状态，通常无法再续费或赎回。删除后域名将重新向公众开放注册，如有需要可关注抢注时机。",
      urgency: "❌ 通常已无法续费", urgencyColor: "#991b1b", urgencyBg: "#fef2f2",
      nextLabel: "预计释放时间", nextDate: p.dropDate, nextColor: "#dc2626",
    },
  }[p.phase];

  return emailLayout(`
    ${colorHeader(cfg.bg, cfg.label, domainBadge(p.domain), "域名生命周期状态变更通知")}

    ${section(`
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">原过期日期</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:#1e293b;font-family:monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:${cfg.badgeBg}">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:${cfg.badgeColor};text-transform:uppercase">当前状态 · ${cfg.badge}</p>
        </div>
        ${cfg.nextDate ? `
        <div style="padding:12px 18px;border-top:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${cfg.nextLabel}</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:${cfg.nextColor};font-family:monospace">${cfg.nextDate}</p>
        </div>` : ""}
      </div>

      <p style="margin:0 0 14px;font-size:13px;color:#475569;line-height:1.8">${cfg.body}</p>

      <div style="padding:12px 16px;background:${cfg.urgencyBg};border:1px solid ${cfg.badgeBg};border-radius:8px">
        <p style="margin:0;font-size:12px;font-weight:700;color:${cfg.urgencyColor}">${cfg.urgency}</p>
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, "查看域名详情", cancelUrl, cfg.bg)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 5a. Domain drop approaching (7 days before drop date)
// ──────────────────────────────────────────────────────────────────────────────
export interface DropApproachingParams {
  domain: string;
  expirationDate: string | null;
  dropDate: string;
  daysToDropDate: number;
  cancelToken: string;
}

export function dropApproachingHtml(p: DropApproachingParams & { siteName?: string }): string {
  const siteName = p.siteName || "X.RW";
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = p.expirationDate
    ? new Date(p.expirationDate).toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric" })
    : "未知";
  const urgency = p.daysToDropDate <= 1 ? "🔴 明日起可抢注" : `⚡ ${p.daysToDropDate} 天后可抢注`;

  return emailLayout(`
    ${colorHeader("#7c3aed", "域名即将可注册", domainBadge(p.domain), "该域名即将进入可注册状态")}

    ${section(`
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">原过期日期</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:#1e293b;font-family:monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:#f5f3ff;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:#7c3aed;text-transform:uppercase">预计可注册日期</p>
          <p style="margin:6px 0 0;font-size:20px;font-weight:800;color:#7c3aed;font-family:ui-monospace,'Fira Code',monospace">${p.dropDate}</p>
        </div>
        <div style="padding:12px 18px;background:#faf5ff">
          <p style="margin:0;font-size:13px;color:#475569;line-height:1.7">
            域名已完成所有保留期，即将从注册局释放。若您有意注册此域名，请关注各大注册商的抢注服务，通常在释放后数小时至数天内可完成注册。
          </p>
        </div>
      </div>

      <div style="padding:12px 16px;background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;margin-bottom:14px">
        <p style="margin:0;font-size:12px;font-weight:700;color:#6d28d9">${urgency}</p>
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, "查看域名详情", cancelUrl, "#7c3aed")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 5b. Domain dropped / now available
// ──────────────────────────────────────────────────────────────────────────────
export interface DomainDroppedParams {
  domain: string;
  expirationDate: string | null;
  cancelToken: string;
}

export function domainDroppedHtml(p: DomainDroppedParams & { siteName?: string }): string {
  const siteName = p.siteName || "X.RW";
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = p.expirationDate
    ? new Date(p.expirationDate).toLocaleDateString("zh-CN", { year: "numeric", month: "long", day: "numeric" })
    : "未知";

  return emailLayout(`
    ${colorHeader("#059669", "域名已释放 · 可以注册了", domainBadge(p.domain), "该域名已重新开放注册")}

    ${section(`
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">原过期日期</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:#1e293b;font-family:monospace">${expiryStr}</p>
        </div>
        <div style="padding:14px 18px;background:#ecfdf5">
          <p style="margin:0;font-size:13px;font-weight:700;color:#059669">✅ 域名已完成所有保留期，现已向公众开放注册。</p>
          <p style="margin:8px 0 0;font-size:12px;color:#475569;line-height:1.7">
            请前往你的注册商查看是否可以注册。部分域名释放后会进入抢注竞价流程，可关注 DropCatch、NameJet 等平台。
          </p>
        </div>
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, "查看域名详情", cancelUrl, "#059669")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. Password reset email
// ──────────────────────────────────────────────────────────────────────────────
export function passwordResetHtml({ resetUrl, siteName = "X.RW" }: { resetUrl: string; siteName?: string }): string {
  return emailLayout(`
    ${darkHeader("账户安全", "重置您的密码")}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:#64748b;line-height:1.8">
        我们收到了您的密码重置请求。点击下方按钮设置新密码，链接在 <strong style="color:#1e293b">60 分钟</strong>内有效。
      </p>
      ${ctaBtn(resetUrl, "重置密码", PRIMARY)}
      <div style="margin:22px 0 0;padding:14px 16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
        <p style="margin:0;font-size:11px;color:#94a3b8;line-height:1.7">
          如果按钮无法点击，请复制以下链接到浏览器地址栏：<br/>
          <a href="${resetUrl}" style="color:${PRIMARY};font-size:11px;word-break:break-all">${resetUrl}</a>
        </p>
      </div>
      <p style="margin:16px 0 0;font-size:11px;color:#94a3b8;line-height:1.7">
        如非您本人操作，请忽略此邮件，您的账户安全不受影响。
      </p>
    `)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. Admin test / notification email
// ──────────────────────────────────────────────────────────────────────────────
export function adminNotifyHtml({ subject, body, siteName = "X.RW" }: { subject: string; body: string; siteName?: string }): string {
  return emailLayout(`
    ${darkHeader("管理员通知", subject)}
    ${section(`<p style="margin:0;font-size:13px;color:#475569;line-height:1.8">${body}</p>`)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. Feedback notification email (sent to admin)
// ──────────────────────────────────────────────────────────────────────────────
export function feedbackHtml({
  query, queryType, issueLabels, description, email, ip, ts, siteName = "X.RW",
}: {
  query: string;
  queryType: string;
  issueLabels: string;
  description?: string;
  email?: string;
  ip: string;
  ts: string;
  siteName?: string;
}): string {
  const rows = [
    kvRow("查询目标", `<span style="font-family:monospace">${query}</span>`),
    kvRow("查询类型", queryType),
    kvRow("问题类型", `<span style="color:#dc2626">${issueLabels}</span>`),
    ...(description ? [kvRow("补充说明", `<span style="white-space:pre-wrap">${description}</span>`)] : []),
    ...(email ? [kvRow("联系邮箱", `<a href="mailto:${email}" style="color:${PRIMARY}">${email}</a>`)] : []),
  ];

  return emailLayout(`
    ${darkHeader("用户反馈", query, ts + "（北京时间）")}

    ${section(`
      <table cellpadding="0" cellspacing="0" style="width:100%">
        ${rows.join("")}
      </table>
    `)}

    ${divider()}
    <div style="padding:14px 32px;background:#f8fafc">
      <p style="margin:0;font-size:11px;color:#94a3b8">IP：${ip} · 来源：${siteName} 反馈系统</p>
    </div>
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. High-value available domain alert (sent to admin)
// ──────────────────────────────────────────────────────────────────────────────
export interface HighValueAlertParams {
  domain: string;
  score: number;
  tier: string;
  reasons: string[];
  isAlertKeyword: boolean;
  isNumericOnly: boolean;
  checkedBy?: string | null;
  breakdown: { lengthScore: number; tldScore: number; keywordScore: number; patternScore: number };
  hotPrefix?: {
    prefix: string;
    category: string;
    weight: number;
    matchType: "exact" | "contains";
    saleExamples?: string | null;
    notes?: string | null;
  } | null;
  aiSummary?: string | null;
}

export function highValueAlertHtml(p: HighValueAlertParams & { siteName?: string }): string {
  const siteName = p.siteName || "X.RW";
  const ALERT_COLOR = p.score >= 80 ? "#dc2626" : p.score >= 60 ? "#d97706" : "#7c3aed";
  const tierBg     = p.score >= 80 ? "#fef2f2" : p.score >= 60 ? "#fffbeb" : "#ede9fe";
  const tierColor  = p.score >= 80 ? "#991b1b" : p.score >= 60 ? "#92400e" : "#5b21b6";
  const LOOKUP_URL = `${BASE_URL()}/${p.domain}`;

  const labelRow = (l: string, v: string) =>
    `<tr><td style="padding:8px 0;font-size:12px;color:#94a3b8;font-weight:500;width:90px;vertical-align:top;border-bottom:1px solid #f1f5f9">${l}</td><td style="padding:8px 0;font-size:13px;color:#1e293b;font-weight:600;border-bottom:1px solid #f1f5f9">${v}</td></tr>`;

  const scoreBar = (label: string, val: number, max: number, color: string) => {
    const pct = Math.round((val / max) * 100);
    return `<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:11px;color:#64748b">${label}</span>
        <span style="font-size:11px;font-weight:700;color:${color}">${val}/${max}</span>
      </div>
      <div style="height:6px;background:#f1f5f9;border-radius:999px;overflow:hidden">
        <div style="height:6px;width:${pct}%;background:${color};border-radius:999px"></div>
      </div>
    </div>`;
  };

  return emailLayout(`
    <div style="background:${ALERT_COLOR};padding:28px 32px 24px;position:relative">
      <p style="margin:0;font-size:10px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,.5);text-transform:uppercase">
        ${p.isAlertKeyword ? "⚡ 特殊关键词可用告警" : "💎 高价值域名可用告警"}
      </p>
      <h1 style="margin:8px 0 6px;font-size:26px;font-weight:900;color:#fff;font-family:ui-monospace,'Fira Code',monospace;letter-spacing:-0.5px">
        ${p.domain}
      </h1>
      <p style="margin:0;font-size:13px;color:rgba(255,255,255,.7)">该域名当前未被注册，请及时评估并决定是否注册</p>
    </div>

    ${section(`
      <!-- Score badge -->
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap">
        <div style="background:${tierBg};border:2px solid ${ALERT_COLOR}22;border-radius:16px;padding:14px 20px;text-align:center;min-width:90px">
          <p style="margin:0;font-size:32px;font-weight:900;color:${ALERT_COLOR};line-height:1">${p.score}</p>
          <p style="margin:4px 0 0;font-size:10px;font-weight:700;letter-spacing:1px;color:${tierColor};text-transform:uppercase">价值评分</p>
        </div>
        <div>
          <div style="display:inline-block;background:${tierBg};border:1px solid ${ALERT_COLOR}44;color:${tierColor};padding:4px 14px;border-radius:999px;font-size:13px;font-weight:700;margin-bottom:8px">
            ${p.tier}价值
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${p.reasons.map(r => pill(r, tierBg, tierColor)).join("")}
            ${p.isAlertKeyword ? pill("⚡ 特殊关键词", "#fef3c7", "#92400e") : ""}
            ${p.isNumericOnly ? pill("🔢 纯数字", "#ecfdf5", "#065f46") : ""}
            ${p.hotPrefix ? pill(`🔥 热门前缀: ${p.hotPrefix.prefix}`, "#fff7ed", "#c2410c") : ""}
          </div>
        </div>
      </div>

      <!-- Hot Prefix Alert (if matched) -->
      ${p.hotPrefix ? `<div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:1px;color:#c2410c;text-transform:uppercase">🔥 热门前缀监控命中</p>
        <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
          <span style="font-family:monospace;font-size:16px;font-weight:800;color:#c2410c;background:#fed7aa;padding:4px 12px;border-radius:8px">${p.hotPrefix.prefix}</span>
          <span style="font-size:12px;color:#78350f">分类：${p.hotPrefix.category} &nbsp;·&nbsp; 权重：${p.hotPrefix.weight} &nbsp;·&nbsp; 匹配：${p.hotPrefix.matchType === "exact" ? "精确" : "前缀"}</span>
        </div>
        ${p.hotPrefix.notes ? `<p style="margin:8px 0 0;font-size:12px;color:#92400e">${p.hotPrefix.notes}</p>` : ""}
        ${p.hotPrefix.saleExamples ? `<p style="margin:6px 0 0;font-size:11px;color:#b45309;font-style:italic">参考成交：${p.hotPrefix.saleExamples}</p>` : ""}
      </div>` : ""}

      <!-- Score breakdown -->
      <div style="background:#f8fafc;border-radius:12px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 12px;font-size:11px;font-weight:700;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">评分明细</p>
        ${scoreBar("名称长度", p.breakdown.lengthScore, 30, "#3b82f6")}
        ${scoreBar("后缀价值", p.breakdown.tldScore, 20, "#8b5cf6")}
        ${scoreBar("热词匹配", p.breakdown.keywordScore, 25, "#f59e0b")}
        ${scoreBar("特征加分", p.breakdown.patternScore, 15, "#10b981")}
      </div>

      <!-- AI Analysis Summary (if available) -->
      ${p.aiSummary ? `<div style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:12px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:1px;color:#6d28d9;text-transform:uppercase">🤖 AI 快速评估</p>
        <p style="margin:0;font-size:13px;color:#3730a3;line-height:1.6">${p.aiSummary}</p>
      </div>` : ""}

      <!-- Info table -->
      <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:20px">
        ${labelRow("域名", `<span style="font-family:monospace;font-size:15px;color:#1e293b">${p.domain}</span>`)}
        ${labelRow("状态", `<span style="color:#059669;font-weight:700">✓ 可注册（未被注册）</span>`)}
        ${p.checkedBy ? labelRow("查询者", p.checkedBy) : ""}
        ${labelRow("检测时间", new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }) + "（北京时间）")}
      </table>
    `)}

    ${divider()}
    <div style="padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
      ${ctaBtn(LOOKUP_URL, "立即查看域名详情", ALERT_COLOR)}
      <a href="https://www.namesilo.com/domain/search-domains?query=${encodeURIComponent(p.domain)}"
         style="font-size:12px;color:#7c3aed;text-decoration:underline;text-underline-offset:3px">
        前往 NameSilo 注册 →
      </a>
    </div>
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// Sending helper — supports SMTP (db-configured) or Resend (env var)
// ──────────────────────────────────────────────────────────────────────────────
const RESEND_FALLBACK_FROM = "onboarding@resend.dev";

type SmtpConfig = {
  host: string;
  port: number;
  user: string;
  pass: string;
  from: string;
  secure: string; // "ssl" | "starttls" | "none"
};

async function getSmtpConfig(): Promise<SmtpConfig | null> {
  try {
    const rows = await import("@/lib/db-query").then(m =>
      m.many<{ key: string; value: string }>(
        `SELECT key, value FROM site_settings WHERE key IN
         ('smtp_enabled','smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from','smtp_secure')`
      )
    );
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    if (!map.smtp_enabled || map.smtp_enabled === "") return null;
    if (!map.smtp_host || !map.smtp_user || !map.smtp_pass) return null;
    return {
      host: map.smtp_host,
      port: parseInt(map.smtp_port || "465"),
      user: map.smtp_user,
      pass: map.smtp_pass,
      from: map.smtp_from || map.smtp_user,
      secure: map.smtp_secure || "ssl",
    };
  } catch {
    return null;
  }
}

/**
 * Format an email address with a display name if it doesn't already have one.
 * "noreply@x.rw" → "X.RW <noreply@x.rw>"
 * "X.RW <noreply@x.rw>" → unchanged (already has a name)
 */
function withSenderName(email: string, name: string): string {
  if (!email || email.includes("<")) return email;
  const safeName = name.replace(/[<>"]/g, "").trim() || "X.RW";
  return `${safeName} <${email}>`;
}

async function sendViaSMTP(smtp: SmtpConfig, to: string, subject: string, html: string) {
  const siteLabel = await getSiteLabel();
  const nodemailer = await import("nodemailer");
  const transporter = nodemailer.default.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.secure === "ssl",
    requireTLS: smtp.secure === "starttls",
    auth: { user: smtp.user, pass: smtp.pass },
    tls: { rejectUnauthorized: false },
  });
  await transporter.sendMail({ from: withSenderName(smtp.from, siteLabel), to, subject, html });
}

async function sendViaResend(to: string, subject: string, html: string) {
  // DB-first with env var fallback
  let resendKey = "";
  let configuredFrom = "";
  try {
    const rows = await import("@/lib/db-query").then(m =>
      m.many<{ key: string; value: string }>(
        `SELECT key, value FROM site_settings WHERE key IN ('resend_api_key','resend_from_email')`
      )
    );
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    resendKey = map.resend_api_key || process.env.RESEND_API_KEY || "";
    configuredFrom = map.resend_from_email || process.env.RESEND_FROM_EMAIL || "";
  } catch {
    resendKey = process.env.RESEND_API_KEY || "";
    configuredFrom = process.env.RESEND_FROM_EMAIL || "";
  }
  if (!resendKey) {
    console.warn("[sendEmail] resend_api_key not configured — email skipped");
    return;
  }
  const siteLabel = await getSiteLabel();
  const fromAddresses = configuredFrom
    ? [withSenderName(configuredFrom, siteLabel), RESEND_FALLBACK_FROM]
    : [RESEND_FALLBACK_FROM];

  for (const from of fromAddresses) {
    try {
      const resp = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ from, to, subject, html }),
      });
      if (resp.ok) return;
      const body = await resp.text().catch(() => "");
      if (resp.status === 403 && body.includes("not verified") && from !== RESEND_FALLBACK_FROM) {
        console.warn(`[sendEmail] Domain not verified for "${from}", retrying with ${RESEND_FALLBACK_FROM}`);
        continue;
      }
      console.error("[sendEmail] Resend error:", resp.status, body);
      return;
    } catch (err: any) {
      console.error("[sendEmail] Resend fetch error:", err.message);
      return;
    }
  }
}

export async function sendEmail({
  to, subject, html,
}: { to: string; subject: string; html: string }) {
  try {
    const smtp = await getSmtpConfig();
    if (smtp) {
      await sendViaSMTP(smtp, to, subject, html);
      return;
    }
  } catch (err: any) {
    console.error("[sendEmail] SMTP error:", err.message);
    return;
  }
  await sendViaResend(to, subject, html);
}

// ──────────────────────────────────────────────────────────────────────────────
// 9. Stamp DNS verification timeout (sent to user, replaces giveup-notify raw HTML)
// ──────────────────────────────────────────────────────────────────────────────
export function stampVerifyTimeoutHtml({
  domain, fileContent, verifyUrl, siteName = "X.RW",
}: {
  domain: string;
  fileContent: string;
  verifyUrl: string;
  siteName?: string;
}): string {
  return emailLayout(`
    ${colorHeader("#ef4444", "域名验证超时", domainBadge(domain), "DNS 验证未在规定时间内完成")}

    ${section(`
      <p style="margin:0 0 18px;font-size:13px;color:#475569;line-height:1.8">
        您的域名 DNS 验证已超时，请改用<strong style="color:#1e293b">文件验证</strong>方式完成品牌认领。
      </p>

      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:14px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">第一步 — 创建验证文件</p>
          <p style="margin:8px 0 0;font-size:13px;color:#1e293b">在域名根目录创建文件路径：</p>
          <p style="margin:6px 0 0;font-family:ui-monospace,'Fira Code',monospace;font-size:12px;color:#7c3aed;background:#f5f3ff;padding:8px 12px;border-radius:6px;word-break:break-all">
            /.well-known/next-whois-verify.txt
          </p>
        </div>
        <div style="padding:14px 18px;background:#f8fafc">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">第二步 — 文件内容（一行）</p>
          <p style="margin:8px 0 0;font-family:ui-monospace,'Fira Code',monospace;font-size:12px;color:#1e293b;background:#f1f5f9;padding:10px 14px;border-radius:6px;word-break:break-all">${fileContent}</p>
        </div>
        <div style="padding:12px 18px;border-top:1px solid #e2e8f0">
          <p style="margin:0;font-size:12px;color:#64748b;line-height:1.7">完成后返回验证页面，点击<strong>重新验证</strong>即可。</p>
        </div>
      </div>
    `)}

    ${divider()}
    ${actionRow(verifyUrl, "返回验证页面", undefined, "#ef4444")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 11. Payment confirmation
// ──────────────────────────────────────────────────────────────────────────────
export function paymentConfirmHtml({
  name, email, planName, amount, currency, orderId, siteName = "X.RW",
}: {
  name?: string | null;
  email: string;
  planName: string;
  amount: number;
  currency: string;
  orderId: string;
  siteName?: string;
}): string {
  const greeting = name ? `你好，${name}` : "你好";
  const fmtAmount = currency.toUpperCase() === "CNY"
    ? `¥${amount.toFixed(2)}`
    : currency.toUpperCase() === "USD"
      ? `$${amount.toFixed(2)}`
      : `${amount.toFixed(2)} ${currency.toUpperCase()}`;
  return emailLayout(`
    ${darkHeader("支付成功", "订阅已开通", "感谢您的支持，您的会员权益已立即生效")}
    ${section(`
      <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.7">${greeting}，您的支付已成功，会员订阅权限已开通，即刻起可使用所有付费功能。</p>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;padding:20px 24px;margin-bottom:20px">
        <p style="margin:0 0 14px;font-size:11px;font-weight:700;letter-spacing:1.5px;color:#166534;text-transform:uppercase">订单详情</p>
        <table cellpadding="0" cellspacing="0" style="width:100%">
          ${kvRow("订单号", `<span style="font-family:monospace;font-size:12px">${orderId}</span>`)}
          ${kvRow("套餐", planName)}
          ${kvRow("金额", `<strong style="color:#059669">${fmtAmount}</strong>`)}
          ${kvRow("账号", email)}
          ${kvRow("生效时间", new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }) + "（北京时间）")}
        </table>
      </div>
      <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6">如有任何疑问，请联系我们的客服支持。</p>
    `)}
    ${divider()}
    ${actionRow(`${BASE_URL()}/dashboard`, "前往用户中心")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 12. Password changed security notification
// ──────────────────────────────────────────────────────────────────────────────
export function passwordChangedHtml({
  name, email, siteName = "X.RW",
}: {
  name?: string | null;
  email: string;
  siteName?: string;
}): string {
  const greeting = name ? `你好，${name}` : "你好";
  const time = new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }) + "（北京时间）";
  return emailLayout(`
    ${colorHeader("#f59e0b", "安全提醒", "账号密码已修改", "如非本人操作，请立即联系客服")}
    ${section(`
      <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.7">
        ${greeting}，您的 <strong style="color:#1e293b">${siteName}</strong> 账号密码已于 <strong>${time}</strong> 修改成功。
      </p>
      <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:12px;padding:16px 20px;margin-bottom:20px">
        <p style="margin:0;font-size:13px;color:#92400e;line-height:1.7">
          ⚠️ 如果这不是您本人操作，请立即通过"忘记密码"功能重置密码，或联系客服处理。
        </p>
      </div>
      <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6">账号：${email}</p>
    `)}
    ${divider()}
    ${actionRow(`${BASE_URL()}/forgot-password`, "前往重置密码", undefined, "#f59e0b")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 13. Admin broadcast / notification email
// ──────────────────────────────────────────────────────────────────────────────
export function adminBroadcastHtml({
  subject, bodyHtml, siteName = "X.RW",
}: {
  subject: string;
  bodyHtml: string;
  siteName?: string;
}): string {
  return emailLayout(`
    ${darkHeader("站点通知", subject)}
    ${section(`
      <div style="font-size:14px;color:#475569;line-height:1.8">
        ${bodyHtml}
      </div>
    `)}
    ${divider()}
    ${actionRow(`${BASE_URL()}`, "前往站点")}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 10. Email verification code
// ──────────────────────────────────────────────────────────────────────────────
export function verifyCodeHtml({ code, email, siteName = "X.RW" }: { code: string; email: string; siteName?: string }): string {
  return emailLayout(`
    ${darkHeader("账号注册", "邮箱验证码", "请在注册页面填写以下验证码完成账号创建")}
    ${section(`
      <p style="margin:0 0 24px;font-size:14px;color:#475569;line-height:1.7">
        你正在注册 <strong style="color:#1e293b">${siteName}</strong> 账号，邮箱地址为：<br/>
        <span style="font-family:monospace;font-size:13px;color:#7c3aed;font-weight:600">${email}</span>
      </p>
      <div style="background:#f8fafc;border:2px dashed #c4b5fd;border-radius:16px;padding:28px;text-align:center;margin-bottom:24px">
        <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:3px;color:#94a3b8;text-transform:uppercase">验证码</p>
        <p style="margin:0;font-size:40px;font-weight:800;letter-spacing:12px;color:#7c3aed;font-family:ui-monospace,'Fira Code',monospace">${code}</p>
        <p style="margin:12px 0 0;font-size:12px;color:#94a3b8">10 分钟内有效</p>
      </div>
      <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.6">
        如果你没有在 ${siteName} 发起注册请求，请忽略此邮件。<br/>
        请勿将验证码分享给任何人。
      </p>
    `)}
    ${divider()}
    ${actionRow(`${BASE_URL()}`, "前往登录")}
  `, siteName);
}
