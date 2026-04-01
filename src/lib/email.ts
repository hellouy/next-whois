/**
 * Shared email helpers — send via SMTP or Resend, consistent HTML template.
 * All user-facing templates accept an optional `locale` parameter.
 */

import { one } from "@/lib/db-query";
import { getEmailStrings, fmtEmailDate } from "@/lib/email-strings";

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

function emailLayout(body: string, siteName = "X.RW", opts?: { langCode?: string; autoSentText?: string }): string {
  const year = new Date().getFullYear();
  const langCode   = opts?.langCode ?? "und";
  const autoSent   = opts?.autoSentText ?? `This email was sent automatically by ${siteName}. Please do not reply.`;

  const parts = siteName.trim().split(" ");
  const head = parts.length > 1 ? parts.slice(0, -1).join(" ") : "";
  const tail = parts[parts.length - 1];
  const logoHtml = head
    ? `${head}&thinsp;<span style="color:${PRIMARY}">${tail}</span>`
    : `<span style="color:${PRIMARY}">${tail}</span>`;

  return `<!DOCTYPE html>
<html lang="${langCode}">
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
              ${autoSent.replace(siteName, `<a href="${BASE_URL()}" style="color:${PRIMARY};text-decoration:none">${siteName}</a>`)}
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
function actionRow(btnHref: string, btnLabel: string, cancelHref?: string, btnColor = PRIMARY, unsubLabel = "Unsubscribe") {
  return `<div style="padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
    ${ctaBtn(btnHref, btnLabel, btnColor)}
    ${cancelHref ? ghostLink(cancelHref, unsubLabel) : ""}
  </div>`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. Welcome email
// ──────────────────────────────────────────────────────────────────────────────
export function welcomeHtml({ name, email, siteName = "X.RW", locale }: {
  name?: string | null; email: string; siteName?: string; locale?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${darkHeader(s.w_label, s.w_title(name), s.w_sub)}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:#64748b;line-height:1.9">
        ${s.w_intro(siteName)}
      </p>

      <!-- Features grid -->
      <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:24px">
        ${s.w_features.map(([icon, title, desc]) => `
          <tr>
            <td style="width:42px;padding:10px 12px 10px 0;vertical-align:top;font-size:20px;line-height:1">${icon}</td>
            <td style="padding:10px 0;border-bottom:1px solid #f1f5f9">
              <p style="margin:0;font-size:13px;font-weight:700;color:#1e293b">${title}</p>
              <p style="margin:3px 0 0;font-size:12px;color:#94a3b8;line-height:1.6">${desc}</p>
            </td>
          </tr>
        `).join("")}
      </table>

      <!-- Getting started steps -->
      <div style="background:#f8f7ff;border:1px solid #ede9fe;border-radius:12px;padding:18px 20px;margin-bottom:22px">
        <p style="margin:0 0 14px;font-size:11px;font-weight:700;letter-spacing:1px;color:#7c3aed;text-transform:uppercase">${s.w_gs_label}</p>
        ${[s.w_gs_step1, s.w_gs_step2, s.w_gs_step3].map((step, i) => `
          <div style="display:flex;align-items:flex-start;gap:12px;${i < 2 ? "margin-bottom:12px" : ""}">
            <span style="flex-shrink:0;width:22px;height:22px;background:#7c3aed;color:#fff;border-radius:50%;font-size:11px;font-weight:800;display:inline-flex;align-items:center;justify-content:center;line-height:1">${i + 1}</span>
            <span style="font-size:12px;color:#475569;line-height:1.7;padding-top:2px">${step}</span>
          </div>
        `).join("")}
      </div>

      <!-- Account login info -->
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:13px 16px">
        <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase;margin-bottom:5px">${s.w_login_label}</p>
        <p style="margin:0;font-family:ui-monospace,'Fira Code',monospace;font-size:13px;color:#334155;font-weight:600">${email}</p>
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}`, s.w_cta)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
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

export function subscriptionConfirmHtml(p: SubscriptionEmailParams & { siteName?: string; locale?: string }): string {
  const siteName  = p.siteName || "X.RW";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const isRestricted = p.regStatusType === "prohibited" || p.regStatusType === "reserved";

  // ── Restricted domain email (prohibited / reserved) ──────────────────────
  if (isRestricted) {
    const isProhibited  = p.regStatusType === "prohibited";
    const statusLabel   = isProhibited ? s.sc_prohibited_label : s.sc_reserved_label;
    const statusColor   = isProhibited ? "#dc2626" : "#d97706";
    const statusBg      = isProhibited ? "#fef2f2" : "#fffbeb";
    const statusDesc    = isProhibited ? s.sc_restricted_prohibited_desc : s.sc_restricted_reserved_desc;

    return emailLayout(`
      ${darkHeader(s.sc_restricted_label, domainBadge(p.domain), s.sc_restricted_sub)}

      ${section(`
        <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:20px">
          <div style="padding:12px 18px;background:${statusBg}">
            <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:${statusColor};text-transform:uppercase">${s.sc_current_status} · ${statusLabel}</p>
            <p style="margin:6px 0 0;font-size:12px;color:#475569;line-height:1.7">${statusDesc}</p>
          </div>
          <div style="padding:12px 18px;border-top:1px solid #e2e8f0;background:#f0f9ff">
            <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:#0284c7;text-transform:uppercase">${s.sc_subscribed}</p>
            <p style="margin:6px 0 0;font-size:13px;font-weight:700;color:#0c4a6e">✓ ${s.sc_subscribed_desc}</p>
          </div>
        </div>
      `)}

      ${divider()}
      ${actionRow(`${BASE_URL()}/${p.domain}`, s.sc_view_domain, cancelUrl, PRIMARY, s.unsubscribe)}
    `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
  }

  // ── Normal domain email ───────────────────────────────────────────────────
  const expiryStr = fmtEmailDate(p.expirationDate, s);

  const phaseColors: Record<string, { color: string; bg: string }> = {
    active:        { color: "#059669", bg: "#ecfdf5" },
    grace:         { color: "#d97706", bg: "#fffbeb" },
    redemption:    { color: "#ea580c", bg: "#fff7ed" },
    pendingDelete: { color: "#dc2626", bg: "#fef2f2" },
    dropped:       { color: "#6b7280", bg: "#f9fafb" },
  };
  const lc = p.lifecycle;
  const phaseKey = lc?.phase ?? "active";
  const phaseI18n = s.sc_phases[phaseKey] ?? s.sc_phases.active;
  const phaseC = phaseColors[phaseKey] ?? phaseColors.active;

  // Reminder thresholds label: use a generic "N days before" (locale-neutral number)
  const thresholdPills = p.thresholds.map(d =>
    pill(`${d}d`, "#ede9fe", "#5b21b6")
  ).join("");

  return emailLayout(`
    ${darkHeader(s.sc_label, domainBadge(p.domain), s.sc_sub)}

    ${section(`
      <!-- Active monitoring banner -->
      <div style="background:#ecfdf5;border:1px solid #bbf7d0;border-radius:10px;padding:11px 16px;margin-bottom:20px;display:flex;align-items:center;gap:10px">
        <span style="font-size:15px">✅</span>
        <div>
          <p style="margin:0;font-size:12px;font-weight:700;color:#065f46">${s.sc_subscribed}</p>
          <p style="margin:2px 0 0;font-size:11px;color:#047857">${s.sc_subscribed_desc}</p>
        </div>
      </div>

      <!-- Info block -->
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:20px">
        <div style="padding:14px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.sc_expiry_date}</p>
          <p style="margin:6px 0 0;font-size:22px;font-weight:800;color:#1e293b;font-family:ui-monospace,'Fira Code',monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:${phaseC.bg}">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:${phaseC.color};text-transform:uppercase">${s.sc_current_status} · ${phaseI18n.label}</p>
          <p style="margin:6px 0 0;font-size:12px;color:#475569;line-height:1.7">${phaseI18n.desc}</p>
        </div>
      </div>

      <!-- Thresholds -->
      <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#1e293b">${s.sc_reminder_nodes}</p>
      <div style="margin-bottom:${lc && (lc.hasGrace || lc.hasRedemption || lc.hasPendingDelete) ? "16px" : "0"}">
        ${thresholdPills}
      </div>
      ${lc && (lc.hasGrace || lc.hasRedemption || lc.hasPendingDelete) ? `
      <p style="margin:8px 0 8px;font-size:12px;font-weight:700;color:#1e293b">${s.sc_phase_alerts}</p>
      <div>
        ${lc.hasGrace         ? pill(s.sc_grace_pill, "#fffbeb", "#d97706") : ""}
        ${lc.hasRedemption    ? pill(s.sc_redemption_pill, "#fff7ed", "#ea580c") : ""}
        ${lc.hasPendingDelete ? pill(s.sc_pending_pill, "#fef2f2", "#dc2626") : ""}
      </div>` : ""}
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, s.sc_view_domain, cancelUrl, PRIMARY, s.unsubscribe)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Expiry reminder email
// ──────────────────────────────────────────────────────────────────────────────
export function reminderHtml({
  domain, expirationDate, daysLeft, cancelToken, siteName = "X.RW",
  registrar, creationDate, nameservers, locale,
}: {
  domain: string; expirationDate: string | null; daysLeft: number; cancelToken: string; siteName?: string;
  registrar?: string | null; creationDate?: string | null; nameservers?: string[]; locale?: string;
}): string {
  const s         = getEmailStrings(locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${cancelToken}`;
  const expiryStr = fmtEmailDate(expirationDate, s);
  const creationStr = creationDate ? fmtEmailDate(creationDate, s) : null;

  const urgent = daysLeft <= 5;
  const warn   = daysLeft <= 15;
  const hdrBg  = urgent ? "#dc2626" : warn ? "#d97706" : DARK;
  const hdrLabel = urgent ? s.r_urgent_label : s.r_label;
  const btnColor = urgent ? "#dc2626" : warn ? "#d97706" : PRIMARY;

  const bodyText = urgent ? s.r_urgent_body(daysLeft) : s.r_normal_body;

  const extraRows = [
    creationStr ? kvRow(s.r_reg_date, creationStr) : "",
    registrar   ? kvRow(s.r_registrar, registrar)  : "",
    (nameservers && nameservers.length > 0)
      ? kvRow(s.r_nameservers, nameservers.slice(0, 3).map(ns =>
          `<span style="font-family:ui-monospace,monospace;font-size:11px">${ns.toLowerCase()}</span>`
        ).join("<br/>"))
      : "",
  ].filter(Boolean).join("");

  return emailLayout(`
    ${urgent || warn
      ? colorHeader(hdrBg, hdrLabel, domainBadge(domain), s.r_sub(daysLeft))
      : darkHeader(hdrLabel, domainBadge(domain), s.r_sub(daysLeft))}

    ${section(`
      <!-- Large countdown display -->
      <div style="text-align:center;padding:8px 0 18px">
        <p style="margin:0;font-size:72px;font-weight:900;color:${urgent ? "#dc2626" : warn ? "#d97706" : PRIMARY};line-height:1;font-family:ui-monospace,'Fira Code',monospace">${daysLeft}</p>
        <p style="margin:4px 0 0;font-size:12px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">${s.r_expiry_date.toLowerCase()}</p>
      </div>

      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:14px 18px;border-bottom:1px solid #f1f5f9">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.r_expiry_date}</p>
          <p style="margin:6px 0 0;font-size:22px;font-weight:800;color:#1e293b;font-family:ui-monospace,'Fira Code',monospace">${expiryStr}</p>
        </div>
        ${extraRows ? `<div style="padding:4px 18px 8px"><table cellpadding="0" cellspacing="0" style="width:100%">${extraRows}</table></div>` : ""}
      </div>

      <p style="margin:0 0 14px;font-size:13px;color:#475569;line-height:1.8">${bodyText}</p>

      <!-- Renewal tip -->
      <div style="background:#f8f7ff;border:1px solid #ede9fe;border-radius:10px;padding:12px 16px">
        <p style="margin:0;font-size:12px;color:#5b21b6;line-height:1.7">💡 ${s.r_renewal_tip}</p>
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${domain}`, s.r_cta, cancelUrl, btnColor, s.unsubscribe)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
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
  registrar?: string | null;
  creationDate?: string | null;
}

export function phaseEventHtml(p: PhaseEventEmailParams & { siteName?: string; locale?: string }): string {
  const siteName  = p.siteName || "X.RW";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr  = fmtEmailDate(p.expirationDate, s);
  const creationStr = p.creationDate ? fmtEmailDate(p.creationDate, s) : null;

  const cfg = {
    grace: {
      bg: "#d97706",
      label: s.pe_grace_label,
      badge: s.pe_grace_badge,  badgeColor: "#d97706", badgeBg: "#fffbeb",
      body: s.pe_grace_body,
      urgency: s.pe_grace_urgency, urgencyColor: "#92400e", urgencyBg: "#fffbeb",
      nextLabel: s.pe_grace_next_label, nextDate: p.graceEnd, nextColor: "#d97706",
      actions: [s.pe_grace_action1, s.pe_grace_action2, s.pe_grace_action3],
    },
    redemption: {
      bg: "#ea580c",
      label: s.pe_redemption_label,
      badge: s.pe_redemption_badge, badgeColor: "#ea580c", badgeBg: "#fff7ed",
      body: s.pe_redemption_body,
      urgency: s.pe_redemption_urgency, urgencyColor: "#9a3412", urgencyBg: "#fff7ed",
      nextLabel: s.pe_redemption_next_label, nextDate: p.redemptionEnd, nextColor: "#ea580c",
      actions: [s.pe_redemption_action1, s.pe_redemption_action2, s.pe_redemption_action3],
    },
    pendingDelete: {
      bg: "#dc2626",
      label: s.pe_pending_label,
      badge: s.pe_pending_badge, badgeColor: "#dc2626", badgeBg: "#fef2f2",
      body: s.pe_pending_body,
      urgency: s.pe_pending_urgency, urgencyColor: "#991b1b", urgencyBg: "#fef2f2",
      nextLabel: s.pe_pending_next_label, nextDate: p.dropDate, nextColor: "#dc2626",
      actions: [s.pe_pending_action1, s.pe_pending_action2],
    },
  }[p.phase];

  return emailLayout(`
    ${colorHeader(cfg.bg, cfg.label, domainBadge(p.domain), s.pe_sub)}

    ${section(`
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.pe_orig_expiry}</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:#1e293b;font-family:monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:${cfg.badgeBg}">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:${cfg.badgeColor};text-transform:uppercase">${s.pe_current_status} · ${cfg.badge}</p>
        </div>
        ${cfg.nextDate ? `
        <div style="padding:12px 18px;border-top:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${cfg.nextLabel}</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:${cfg.nextColor};font-family:monospace">${cfg.nextDate}</p>
        </div>` : ""}
        ${(creationStr || p.registrar) ? `
        <div style="padding:8px 18px 10px;border-top:1px solid #f1f5f9">
          <table cellpadding="0" cellspacing="0" style="width:100%">
            ${creationStr ? kvRow(s.pe_reg_date, creationStr) : ""}
            ${p.registrar  ? kvRow(s.pe_registrar, p.registrar) : ""}
          </table>
        </div>` : ""}
      </div>

      <p style="margin:0 0 14px;font-size:13px;color:#475569;line-height:1.8">${cfg.body}</p>

      <!-- Urgency notice -->
      <div style="padding:12px 16px;background:${cfg.urgencyBg};border:1px solid ${cfg.badgeBg};border-radius:8px;margin-bottom:16px">
        <p style="margin:0;font-size:12px;font-weight:700;color:${cfg.urgencyColor}">⚠️ ${cfg.urgency}</p>
      </div>

      <!-- Action items -->
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">
        <div style="padding:12px 18px;background:#f8fafc;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:#475569;text-transform:uppercase">${s.pe_action_label}</p>
        </div>
        ${cfg.actions.map((action: string, i: number) => `
          <div style="padding:10px 18px;border-bottom:${i < cfg.actions.length - 1 ? "1px solid #f1f5f9" : "none"};display:flex;align-items:flex-start;gap:12px">
            <span style="flex-shrink:0;width:20px;height:20px;background:${cfg.bg};color:#fff;border-radius:50%;font-size:10px;font-weight:800;display:inline-flex;align-items:center;justify-content:center;line-height:1;margin-top:1px">${i + 1}</span>
            <span style="font-size:12px;color:#475569;line-height:1.7">${action}</span>
          </div>
        `).join("")}
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, s.pe_cta, cancelUrl, cfg.bg, s.unsubscribe)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
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

export function dropApproachingHtml(p: DropApproachingParams & { siteName?: string; locale?: string }): string {
  const siteName  = p.siteName || "X.RW";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = fmtEmailDate(p.expirationDate, s);
  const urgency   = p.daysToDropDate <= 1 ? s.da_urgency_1 : s.da_urgency_n(p.daysToDropDate);

  return emailLayout(`
    ${colorHeader("#7c3aed", s.da_label, domainBadge(p.domain), s.da_sub)}

    ${section(`
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.da_orig_expiry}</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:#1e293b;font-family:monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:#f5f3ff;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:#7c3aed;text-transform:uppercase">${s.da_avail_date}</p>
          <p style="margin:6px 0 0;font-size:24px;font-weight:900;color:#7c3aed;font-family:ui-monospace,'Fira Code',monospace">${p.dropDate}</p>
        </div>
        <div style="padding:12px 18px;background:#faf5ff">
          <p style="margin:0;font-size:13px;color:#475569;line-height:1.7">${s.da_body}</p>
        </div>
      </div>

      <div style="padding:12px 16px;background:#f5f3ff;border:1px solid #ddd6fe;border-radius:8px;margin-bottom:16px">
        <p style="margin:0;font-size:12px;font-weight:700;color:#6d28d9">⚡ ${urgency}</p>
      </div>

      <!-- Registration services -->
      <div style="border:1px solid #e2e8f0;border-radius:10px;padding:14px 18px">
        <p style="margin:0 0 12px;font-size:11px;font-weight:700;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.pe_action_label}</p>
        ${[s.pe_pending_action1, s.pe_pending_action2].map((action, i) => `
          <div style="${i > 0 ? "margin-top:8px;" : ""}display:flex;align-items:flex-start;gap:10px">
            <span style="color:#7c3aed;font-weight:700;font-size:14px;flex-shrink:0">→</span>
            <span style="font-size:12px;color:#475569;line-height:1.7">${action}</span>
          </div>
        `).join("")}
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, s.da_cta, cancelUrl, "#7c3aed", s.unsubscribe)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 5b. Domain dropped / now available
// ──────────────────────────────────────────────────────────────────────────────
export interface DomainDroppedParams {
  domain: string;
  expirationDate: string | null;
  cancelToken: string;
}

export function domainDroppedHtml(p: DomainDroppedParams & { siteName?: string; locale?: string }): string {
  const siteName  = p.siteName || "X.RW";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = fmtEmailDate(p.expirationDate, s);

  return emailLayout(`
    ${colorHeader("#059669", s.dd_label, domainBadge(p.domain), s.dd_sub)}

    ${section(`
      <!-- Available banner -->
      <div style="text-align:center;padding:8px 0 16px">
        <div style="display:inline-block;background:#ecfdf5;border:2px solid #6ee7b7;border-radius:16px;padding:14px 28px">
          <p style="margin:0;font-size:36px;line-height:1">✅</p>
          <p style="margin:6px 0 0;font-size:14px;font-weight:800;color:#065f46">${s.dd_available}</p>
        </div>
      </div>

      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.dd_orig_expiry}</p>
          <p style="margin:6px 0 0;font-size:16px;font-weight:700;color:#1e293b;font-family:monospace">${expiryStr}</p>
        </div>
        <div style="padding:12px 18px;background:#ecfdf5">
          <p style="margin:0;font-size:12px;color:#047857;line-height:1.7">${s.dd_note}</p>
        </div>
      </div>

      <!-- Registration tip -->
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:14px 18px;margin-bottom:16px">
        <p style="margin:0;font-size:12px;color:#166534;line-height:1.7">🏁 ${s.dd_register_tip}</p>
      </div>

      <!-- Registrar links -->
      <div style="border:1px solid #e2e8f0;border-radius:10px;overflow:hidden">
        <div style="padding:11px 18px;background:#f8fafc;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.dd_cta}</p>
        </div>
        ${[
          { name: "Namecheap", url: `https://www.namecheap.com/domains/registration/results/?domain=${p.domain}` },
          { name: "GoDaddy",   url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${p.domain}` },
          { name: "Porkbun",   url: `https://porkbun.com/checkout/search?q=${p.domain}` },
        ].map(r => `
          <div style="padding:11px 18px;border-bottom:1px solid #f1f5f9">
            <a href="${r.url}" style="font-size:13px;font-weight:600;color:#059669;text-decoration:none">${r.name} →</a>
          </div>
        `).join("")}
        <div style="padding:11px 18px">
          <a href="https://www.namesilo.com/domain/search-domains?query=${encodeURIComponent(p.domain)}" style="font-size:13px;font-weight:600;color:#059669;text-decoration:none">NameSilo →</a>
        </div>
      </div>
    `)}

    ${divider()}
    ${actionRow(`${BASE_URL()}/${p.domain}`, s.dd_cta, cancelUrl, "#059669", s.unsubscribe)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. Password reset email
// ──────────────────────────────────────────────────────────────────────────────
export function passwordResetHtml({ resetUrl, siteName = "X.RW", locale }: {
  resetUrl: string; siteName?: string; locale?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${darkHeader(s.pr_label, s.pr_title)}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:#64748b;line-height:1.8">${s.pr_body}</p>

      ${ctaBtn(resetUrl, s.pr_cta, PRIMARY)}

      <div style="margin:22px 0 0;padding:14px 16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
        <p style="margin:0;font-size:11px;color:#94a3b8;line-height:1.7">
          ${s.pr_link_note}<br/>
          <a href="${resetUrl}" style="color:${PRIMARY};font-size:11px;word-break:break-all">${resetUrl}</a>
        </p>
      </div>

      <p style="margin:16px 0 8px;font-size:11px;color:#94a3b8;line-height:1.7">${s.pr_security}</p>

      <!-- Didn't request section -->
      <div style="border-top:1px solid #f1f5f9;margin-top:18px;padding-top:16px">
        <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:#475569">${s.pr_not_you}</p>
        <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.7">${s.pr_not_you_body}</p>
      </div>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. Admin test / notification email  (admin-only — stays in English/Chinese)
// ──────────────────────────────────────────────────────────────────────────────
export function adminNotifyHtml({ subject, body, siteName = "X.RW" }: {
  subject: string; body: string; siteName?: string;
}): string {
  return emailLayout(`
    ${darkHeader("Admin Notification", subject)}
    ${section(`<p style="margin:0;font-size:13px;color:#475569;line-height:1.8">${body}</p>`)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. Feedback notification email (sent to admin — stays in Chinese)
// ──────────────────────────────────────────────────────────────────────────────
export function feedbackHtml({
  query, queryType, issueLabels, description, email, ip, ts, siteName = "X.RW",
}: {
  query: string; queryType: string; issueLabels: string; description?: string;
  email?: string; ip: string; ts: string; siteName?: string;
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
// 9. High-value available domain alert (sent to admin — stays in Chinese)
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
  const tierBg      = p.score >= 80 ? "#fef2f2" : p.score >= 60 ? "#fffbeb" : "#ede9fe";
  const tierColor   = p.score >= 80 ? "#991b1b" : p.score >= 60 ? "#92400e" : "#5b21b6";
  const LOOKUP_URL  = `${BASE_URL()}/${p.domain}`;

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
            ${p.isNumericOnly  ? pill("🔢 纯数字", "#ecfdf5", "#065f46") : ""}
            ${p.hotPrefix      ? pill(`🔥 热门前缀: ${p.hotPrefix.prefix}`, "#fff7ed", "#c2410c") : ""}
          </div>
        </div>
      </div>

      ${p.hotPrefix ? `<div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:1px;color:#c2410c;text-transform:uppercase">🔥 热门前缀监控命中</p>
        <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
          <span style="font-family:monospace;font-size:16px;font-weight:800;color:#c2410c;background:#fed7aa;padding:4px 12px;border-radius:8px">${p.hotPrefix.prefix}</span>
          <span style="font-size:12px;color:#78350f">分类：${p.hotPrefix.category} &nbsp;·&nbsp; 权重：${p.hotPrefix.weight} &nbsp;·&nbsp; 匹配：${p.hotPrefix.matchType === "exact" ? "精确" : "前缀"}</span>
        </div>
        ${p.hotPrefix.notes ? `<p style="margin:8px 0 0;font-size:12px;color:#92400e">${p.hotPrefix.notes}</p>` : ""}
        ${p.hotPrefix.saleExamples ? `<p style="margin:6px 0 0;font-size:11px;color:#b45309;font-style:italic">参考成交：${p.hotPrefix.saleExamples}</p>` : ""}
      </div>` : ""}

      <div style="background:#f8fafc;border-radius:12px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 12px;font-size:11px;font-weight:700;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">评分明细</p>
        ${scoreBar("名称长度", p.breakdown.lengthScore, 30, "#3b82f6")}
        ${scoreBar("后缀价值", p.breakdown.tldScore, 20, "#8b5cf6")}
        ${scoreBar("热词匹配", p.breakdown.keywordScore, 25, "#f59e0b")}
        ${scoreBar("特征加分", p.breakdown.patternScore, 15, "#10b981")}
      </div>

      ${p.aiSummary ? `<div style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:12px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:1px;color:#6d28d9;text-transform:uppercase">🤖 AI 快速评估</p>
        <p style="margin:0;font-size:13px;color:#3730a3;line-height:1.6">${p.aiSummary}</p>
      </div>` : ""}

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
// 10. Stamp DNS verification timeout (sent to user)
// ──────────────────────────────────────────────────────────────────────────────
export function stampVerifyTimeoutHtml({
  domain, fileContent, verifyUrl, siteName = "X.RW", locale,
}: {
  domain: string; fileContent: string; verifyUrl: string; siteName?: string; locale?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${colorHeader("#ef4444", s.sv_label, domainBadge(domain), s.sv_sub)}

    ${section(`
      <p style="margin:0 0 18px;font-size:13px;color:#475569;line-height:1.8">${s.sv_intro}</p>

      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:14px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.sv_step1_title}</p>
          <p style="margin:8px 0 0;font-size:13px;color:#1e293b">${s.sv_step1_body}</p>
          <p style="margin:6px 0 0;font-family:ui-monospace,'Fira Code',monospace;font-size:12px;color:#7c3aed;background:#f5f3ff;padding:8px 12px;border-radius:6px;word-break:break-all">
            /.well-known/next-whois-verify.txt
          </p>
        </div>
        <div style="padding:14px 18px;background:#f8fafc">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.sv_step2_title}</p>
          <p style="margin:8px 0 0;font-family:ui-monospace,'Fira Code',monospace;font-size:12px;color:#1e293b;background:#f1f5f9;padding:10px 14px;border-radius:6px;word-break:break-all">${fileContent}</p>
        </div>
        <div style="padding:12px 18px;border-top:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.sv_step3_title}</p>
          <p style="margin:6px 0 0;font-size:12px;color:#475569">${s.sv_step3_body}</p>
        </div>
      </div>

      ${ctaBtn(verifyUrl, s.sv_cta, "#ef4444")}
      <p style="margin:16px 0 0;font-size:11px;color:#94a3b8">${s.sv_retry}</p>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 11. Password changed notification
// ──────────────────────────────────────────────────────────────────────────────
export function passwordChangedHtml({ siteName = "X.RW", locale, changedAt, name, email }: {
  siteName?: string; locale?: string; changedAt?: string; name?: string | null; email?: string;
}): string {
  const s      = getEmailStrings(locale);
  const baseUrl = BASE_URL();
  const ts     = changedAt || new Date().toLocaleString(s.date_locale, { dateStyle: "medium", timeStyle: "short" });
  return emailLayout(`
    ${colorHeader("#dc2626", s.pc_label, s.pc_title, s.pc_sub)}

    ${section(`
      <p style="margin:0 0 20px;font-size:13px;color:#475569;line-height:1.8">${s.pc_body}</p>

      <!-- Change details -->
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:12px 18px;background:#fef2f2">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.pc_time_label}</p>
          <p style="margin:5px 0 0;font-size:14px;font-weight:700;color:#1e293b;font-family:ui-monospace,monospace">${ts}</p>
        </div>
        <div style="padding:12px 18px;border-top:1px solid #fecaca;background:#fff5f5">
          <p style="margin:0;font-size:12px;color:#ef4444">🔒 ${s.pc_sub}</p>
        </div>
      </div>

      ${ctaBtn(baseUrl + "/account", s.pc_cta, "#dc2626")}

      <!-- Didn't change section -->
      <div style="border-top:1px solid #f1f5f9;margin-top:22px;padding-top:16px;background:#fef2f2;border-radius:10px;padding:14px 18px;margin-top:18px;border:1px solid #fecaca">
        <p style="margin:0 0 6px;font-size:12px;font-weight:700;color:#991b1b">⚠️ ${s.pc_not_you}</p>
        <p style="margin:0;font-size:12px;color:#7f1d1d;line-height:1.7">${s.pc_not_you_body(siteName)}</p>
      </div>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 12. Email verification code
// ──────────────────────────────────────────────────────────────────────────────
export function verifyCodeHtml({ code, siteName = "X.RW", locale, email }: {
  code: string; siteName?: string; locale?: string; email?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${darkHeader(s.vc_label, s.vc_title, s.vc_sub)}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:#64748b;line-height:1.8">${s.vc_body}</p>

      <!-- Large code display -->
      <div style="text-align:center;padding:28px 20px;background:#f5f3ff;border:2px dashed #c4b5fd;border-radius:14px;margin-bottom:22px">
        <p style="margin:0;font-size:46px;font-weight:900;letter-spacing:10px;color:#5b21b6;font-family:ui-monospace,'Fira Code',monospace;line-height:1">${code}</p>
      </div>

      <!-- Expiry info -->
      <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:12px 16px;margin-bottom:14px">
        <p style="margin:0;font-size:12px;color:#92400e;line-height:1.7">⏱️ ${s.vc_expires}</p>
      </div>

      <p style="margin:0;font-size:11px;color:#94a3b8;line-height:1.7;text-align:center">${s.vc_security}</p>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 13. Admin broadcast message (admin → all users)
// ──────────────────────────────────────────────────────────────────────────────
export function adminBroadcastHtml({ subject, body, bodyHtml, siteName = "X.RW", locale }: {
  subject: string; body?: string; bodyHtml?: string; siteName?: string; locale?: string;
}): string {
  const s       = getEmailStrings(locale);
  const content = bodyHtml || (body ? `<p style="margin:0;font-size:13px;color:#475569;line-height:1.9;white-space:pre-wrap">${body}</p>` : "");
  return emailLayout(`
    ${darkHeader(s.ab_label, subject)}

    ${section(content)}

    ${divider()}
    ${actionRow(BASE_URL(), siteName, undefined, PRIMARY)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 14. Payment confirmation
// ──────────────────────────────────────────────────────────────────────────────
export function paymentConfirmHtml({ plan, planName, expiresAt, amount, currency = "USD", orderId, siteName = "X.RW", locale, name, email }: {
  plan?: string; planName?: string; expiresAt?: string | null; amount?: number | string | null;
  currency?: string; orderId?: string; siteName?: string; locale?: string; name?: string | null; email?: string;
}): string {
  const s        = getEmailStrings(locale);
  const planDisp = planName || plan || "—";
  const amtStr   = amount != null ? String(amount) : null;
  return emailLayout(`
    ${colorHeader("#059669", s.pay_label, s.pay_title, s.pay_sub)}

    ${section(`
      <!-- Success banner -->
      <div style="text-align:center;padding:8px 0 20px">
        <div style="display:inline-block;background:#ecfdf5;border:2px solid #6ee7b7;border-radius:50%;width:56px;height:56px;line-height:56px;font-size:28px">✅</div>
      </div>

      <p style="margin:0 0 20px;font-size:13px;color:#475569;line-height:1.8;text-align:center">${s.pay_body}</p>

      <!-- Plan details -->
      <div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:18px">
        <div style="padding:13px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.pay_plan_label}</p>
          <p style="margin:5px 0 0;font-size:16px;font-weight:700;color:#1e293b">${planDisp}</p>
        </div>
        ${orderId ? `
        <div style="padding:13px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">Order ID</p>
          <p style="margin:5px 0 0;font-size:12px;font-weight:600;color:#475569;font-family:ui-monospace,monospace">${orderId}</p>
        </div>` : ""}
        ${expiresAt ? `
        <div style="padding:13px 18px;border-bottom:1px solid #e2e8f0">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.pay_expires_label}</p>
          <p style="margin:5px 0 0;font-size:14px;font-weight:700;color:#1e293b;font-family:ui-monospace,monospace">${expiresAt}</p>
        </div>` : ""}
        ${amtStr ? `
        <div style="padding:13px 18px;background:#ecfdf5">
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:#94a3b8;text-transform:uppercase">${s.pay_amount_label}</p>
          <p style="margin:5px 0 0;font-size:18px;font-weight:800;color:#059669">${currency} ${amtStr}</p>
        </div>` : ""}
      </div>

      <p style="margin:0 0 18px;font-size:11px;color:#94a3b8;line-height:1.7">${s.pay_receipt}</p>

      ${ctaBtn(BASE_URL() + "/account", s.pay_cta, "#059669")}
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
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

function withSenderName(email: string, name: string): string {
  if (!email || email.includes("<")) return email;
  const safeName = name.replace(/[<>"]/g, "").trim() || "X.RW";
  return `${safeName} <${email}>`;
}

async function sendViaSMTP(smtp: SmtpConfig, to: string, subject: string, html: string) {
  const siteLabel  = await getSiteLabel();
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

async function sendViaResend(to: string, subject: string, html: string): Promise<void> {
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
    resendKey       = map.resend_api_key    || process.env.RESEND_API_KEY    || "";
    configuredFrom  = map.resend_from_email || process.env.RESEND_FROM_EMAIL || "";
  } catch {
    resendKey      = process.env.RESEND_API_KEY    || "";
    configuredFrom = process.env.RESEND_FROM_EMAIL || "";
  }
  if (!resendKey) {
    console.warn("[sendEmail] resend_api_key not configured — email skipped (not queued)");
    return;
  }
  const siteLabel    = await getSiteLabel();
  const fromAddresses = configuredFrom
    ? [withSenderName(configuredFrom, siteLabel), RESEND_FALLBACK_FROM]
    : [RESEND_FALLBACK_FROM];

  let lastErr = "";
  for (const from of fromAddresses) {
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
    lastErr = `Resend ${resp.status}: ${body.slice(0, 200)}`;
    console.error("[sendEmail] Resend error:", resp.status, body);
    throw new Error(lastErr);
  }
  if (lastErr) throw new Error(lastErr);
}

/**
 * sendEmailDirect — raw send that throws on failure.
 * Used by the queue processor to retry without re-enqueueing.
 */
export async function sendEmailDirect(to: string, subject: string, html: string): Promise<void> {
  const smtp = await getSmtpConfig();
  if (smtp) {
    await sendViaSMTP(smtp, to, subject, html);
    return;
  }
  await sendViaResend(to, subject, html);
}

/**
 * sendEmail — the public API.
 * On any send failure the email is written to email_queue for later retry.
 * The queue processor (api/admin/process-email-queue) will retry with
 * exponential back-off (2, 4, 8, 16 min) up to max_attempts (default 5).
 */
export async function sendEmail({
  to, subject, html,
}: { to: string; subject: string; html: string }) {
  try {
    await sendEmailDirect(to, subject, html);
  } catch (err: any) {
    console.error(`[sendEmail] Failed — queuing for retry → ${to}: ${err.message}`);
    const { enqueueEmail } = await import("@/lib/email-queue");
    await enqueueEmail(to, subject, html);
  }
}
