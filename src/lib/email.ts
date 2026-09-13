/**
 * Shared email helpers — send via SMTP or Resend, consistent HTML template.
 * All user-facing templates accept an optional `locale` parameter.
 */

import { one } from "@/lib/db-query";
import { getEmailStrings, fmtEmailDate } from "@/lib/email-strings";
import { createLogger } from "@/lib/logger";

const logger = createLogger("email");

// ── Design tokens ────────────────────────────────────────────────────────────
// Mirror the site's monochrome minimalism (see src/styles/globals.css): the
// brand accent is near-black, text is slate-neutral, cards use hairline borders
// on a white canvas. No colour bands, no saturated pills, no emoji — the same
// restraint as the homepage. Tones survive only as accent text + a 4px accent
// bar on the header, never as filled backgrounds.
const PRIMARY    = "#18181b";   // near-black — brand accent (site --primary)
const PRIMARY_LT = "#3f3f46";   // zinc-700 — secondary accent
const DARK       = "#18181b";   // near-black header band / strong surfaces

const INK       = "#18181b";    // headings / strong text
const TEXT      = "#52525b";    // body text
const MUTED     = "#a1a1aa";    // secondary / card labels
const FAINT     = "#d4d4d8";    // tertiary text (footer)
const PANEL     = "#fafafa";    // inset panel background
const BORDER    = "#e4e4e7";    // card borders
const HAIR      = "#f4f4f5";    // dividers
const BG        = "#fafafa";    // email canvas

const FONT = "Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";
const MONO = "ui-monospace,'Fira Code',Consolas,monospace";

/** Semantic status palette — accents only (text + hairline + header bar). */
type Tone = "dark" | "brand" | "success" | "warning" | "danger" | "info";
const TONES: Record<Tone, { fg: string; bg: string; border: string; deep: string }> = {
  dark:    { fg: "#52525b", bg: "#fafafa", border: "#e4e4e7", deep: "#18181b" },
  brand:   { fg: "#52525b", bg: "#fafafa", border: "#e4e4e7", deep: "#18181b" },
  success: { fg: "#15803d", bg: "#fafafa", border: "#e4e4e7", deep: "#166534" },
  warning: { fg: "#b45309", bg: "#fafafa", border: "#e4e4e7", deep: "#92400e" },
  danger:  { fg: "#b91c1c", bg: "#fafafa", border: "#e4e4e7", deep: "#991b1b" },
  info:    { fg: "#0369a1", bg: "#fafafa", border: "#e4e4e7", deep: "#075985" },
};
// ── Server-side base URL (cached, reads og_url from DB) ──────────────────────
// BASE_URL() is called synchronously inside template functions; this cache is
// warmed asynchronously before every send so subsequent renders use the DB value.
let _urlCache: string | null = null;
let _urlCacheAt = 0;
const URL_TTL = 60_000;

export async function getSiteBaseUrl(): Promise<string> {
  if (_urlCache && Date.now() - _urlCacheAt < URL_TTL) return _urlCache;
  try {
    const row = await one<{ value: string }>(
      "SELECT value FROM site_settings WHERE key = 'og_url'"
    );
    const dbUrl = row?.value?.trim();
    _urlCache = (dbUrl && dbUrl.startsWith("http"))
      ? dbUrl.replace(/\/$/, "")
      : (process.env.NEXT_PUBLIC_BASE_URL || "https://example.com");
  } catch {
    _urlCache = process.env.NEXT_PUBLIC_BASE_URL || "https://example.com";
  }
  _urlCacheAt = Date.now();
  return _urlCache!;
}

const BASE_URL = () => _urlCache || process.env.NEXT_PUBLIC_BASE_URL || "https://example.com";

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
    _labelCache = (row?.value?.trim()) || "WHOIS";
  } catch {
    _labelCache = "WHOIS";
  }
  _labelCacheAt = Date.now();
  return _labelCache!;
}

// ── Shared primitives ────────────────────────────────────────────────────────

/** Full HTML document shell: logo → card → footer. */
function emailLayout(body: string, siteName = "WHOIS", opts?: { langCode?: string; autoSentText?: string }): string {
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
<body style="margin:0;padding:0;background:${BG};font-family:${FONT}">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px;background:${BG}">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px">

        <!-- Logo -->
        <tr>
          <td style="padding-bottom:18px;text-align:center">
            <a href="${BASE_URL()}" style="text-decoration:none">
              <span style="font-size:17px;font-weight:700;letter-spacing:0.22em;text-transform:uppercase;color:${INK}">${logoHtml}</span>
            </a>
          </td>
        </tr>

        <!-- Card -->
        <tr>
          <td style="background:#ffffff;border-radius:12px;border:1px solid ${BORDER};overflow:hidden">
            ${body}
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 8px 0;text-align:center">
            <p style="margin:0 0 4px;font-size:11px;color:${MUTED};line-height:1.9">
              ${autoSent.replace(siteName, `<a href="${BASE_URL()}" style="color:${MUTED};text-decoration:none">${siteName}</a>`)}
            </p>
            <p style="margin:0;font-size:11px;color:${FAINT}">
              © ${year} ${siteName}
              <span style="margin:0 6px">·</span>
              <a href="${BASE_URL()}/privacy" style="color:${FAINT};text-decoration:none">Privacy</a>
              <span style="margin:0 6px">·</span>
              <a href="${BASE_URL()}/terms" style="color:${FAINT};text-decoration:none">Terms</a>
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
  return `<span style="font-family:${MONO};font-size:inherit;font-weight:700;letter-spacing:-0.3px">${domain}</span>`;
}

/** Coloured pill tag */
function pill(text: string, bg = "#ffffff", color = "#52525b") {
  return `<span style="display:inline-block;background:${bg};color:${color};border:1px solid ${BORDER};padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;margin:3px 3px 3px 0">${text}</span>`;
}

/** Pill using a semantic tone */
function tonePill(text: string, tone: Tone): string {
  const t = TONES[tone];
  return pill(text, "#ffffff", t.deep);
}

/** Key-value row inside a table */
function kvRow(label: string, value: string, valueStyle = "") {
  return `<tr>
    <td style="padding:10px 0;font-size:12px;color:${MUTED};font-weight:500;width:120px;vertical-align:top;border-bottom:1px solid ${HAIR}">${label}</td>
    <td style="padding:10px 0;font-size:13px;color:${INK};font-weight:600;border-bottom:1px solid ${HAIR};${valueStyle}">${value}</td>
  </tr>`;
}

/** Card section with padding */
function section(html: string, pt = "28px", pr = "32px", pb = "28px", pl = "32px") {
  return `<div style="padding:${pt} ${pr} ${pb} ${pl}">${html}</div>`;
}

/** Thin divider */
function divider() {
  return `<div style="height:1px;background:${HAIR}"></div>`;
}

// ── Header band (unified across every template) ──────────────────────────────
/** Minimal header: white canvas, near-black title, a 4px accent bar on the
 *  left and a hairline underline — mirrors the homepage's monochrome restraint.
 *  The tone only tints the accent bar + eyebrow label; no filled colour band. */
function brandHeader(tone: Tone, label: string, title: string, sub = "", opts?: { titleStyle?: string }): string {
  const t = TONES[tone];
  return `<div style="padding:28px 32px 24px;border-bottom:1px solid ${HAIR};position:relative">
    <div style="position:absolute;top:0;bottom:0;left:0;width:4px;background:${t.deep}"></div>
    <p style="margin:0;font-size:10px;font-weight:600;letter-spacing:2px;color:${MUTED};text-transform:uppercase">${label}</p>
    <h1 style="margin:8px 0 ${sub ? "6px" : "0"};font-size:22px;font-weight:700;color:${INK};line-height:1.3;letter-spacing:-0.3px;${opts?.titleStyle ?? ""}">${title}</h1>
    ${sub ? `<p style="margin:0;font-size:13px;color:${MUTED};line-height:1.6">${sub}</p>` : ""}
  </div>`;
}

// ── Info card (label header + value rows) ─────────────────────────────────────
function card(body: string, opts?: { style?: string }): string {
  return `<div style="border:1px solid ${BORDER};border-radius:12px;overflow:hidden;${opts?.style ?? ""}">${body}</div>`;
}
function cardHead(label: string, opts?: { style?: string }): string {
  return `<div style="padding:12px 18px;border-bottom:1px solid ${HAIR};${opts?.style ?? ""}">
    <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${label}</p>
  </div>`;
}
function cardValue(value: string, opts?: { style?: string }): string {
  return `<p style="margin:0;font-size:20px;font-weight:700;color:${INK};font-family:${MONO};line-height:1.2;letter-spacing:-0.3px;${opts?.style ?? ""}">${value}</p>`;
}
function cardRow(label: string, value: string, opts?: { style?: string; valueStyle?: string }): string {
  return `<div style="padding:11px 18px;border-top:1px solid ${HAIR};${opts?.style ?? ""}">
    <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${label}</p>
    <p style="margin:6px 0 0;font-size:13px;font-weight:600;color:${INK};${opts?.valueStyle ?? ""}">${value}</p>
  </div>`;
}
/** Padded block used inside a card when no label header is needed */
function cardBlock(body: string, opts?: { style?: string }): string {
  return `<div style="padding:12px 18px;${opts?.style ?? ""}">${body}</div>`;
}

/** Callout box with a semantic tone (tips, notices, urgency) — monochrome
 *  panel + hairline border; only the text carries the tone accent. */
function noteBox(text: string, tone: Tone = "info", opts?: { bold?: boolean; style?: string; html?: boolean }): string {
  const t = TONES[tone];
  const inner = opts?.html
    ? text
    : `<p style="margin:0;font-size:12px;color:${t.deep};line-height:1.7;${opts?.bold ? "font-weight:600;" : ""}">${text}</p>`;
  return `<div style="background:${PANEL};border:1px solid ${BORDER};border-left:3px solid ${t.deep};border-radius:6px;padding:12px 16px;${opts?.style ?? ""}">${inner}</div>`;
}

/** Large centered code / value display — hairline box, near-black mono text. */
function codeBox(text: string, opts?: { size?: string; letterSpacing?: string }): string {
  return `<div style="text-align:center;padding:26px 20px;background:${PANEL};border:1px dashed ${FAINT};border-radius:10px">
    <p style="margin:0;font-size:${opts?.size ?? "42px"};font-weight:700;letter-spacing:${opts?.letterSpacing ?? "8px"};color:${INK};font-family:${MONO};line-height:1">${text}</p>
  </div>`;
}

/** Primary CTA button */
function ctaBtn(href: string, label: string, color = PRIMARY) {
  return `<a href="${href}" style="display:inline-block;background:${color};color:#fff;font-size:13px;font-weight:600;padding:11px 24px;border-radius:8px;text-decoration:none;letter-spacing:0.1px">${label} →</a>`;
}

/** Ghost / cancel link */
function ghostLink(href: string, label: string) {
  return `<a href="${href}" style="font-size:11px;color:${MUTED};text-decoration:underline;text-underline-offset:3px">${label}</a>`;
}

// ── Footer action row (button + optional ghost link) ─────────────────────────
function actionRow(btnHref: string, btnLabel: string, cancelHref?: string, btnColor = PRIMARY, unsubLabel = "Unsubscribe") {
  return `<div style="padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
    ${ctaBtn(btnHref, btnLabel, btnColor)}
    ${cancelHref ? ghostLink(cancelHref, unsubLabel) : ""}
  </div>`;
}

/** Divider + action row — the standard email ending */
function actionFooter(btnHref: string, btnLabel: string, opts?: { cancelHref?: string; btnColor?: string; unsubLabel?: string }): string {
  return `${divider()}${actionRow(btnHref, btnLabel, opts?.cancelHref, opts?.btnColor, opts?.unsubLabel)}`;
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. Welcome email
// ──────────────────────────────────────────────────────────────────────────────
export function welcomeHtml({ name, email, siteName = "WHOIS", locale }: {
  name?: string | null; email: string; siteName?: string; locale?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${brandHeader("dark", s.w_label, s.w_title(name), s.w_sub)}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:${TEXT};line-height:1.9">
        ${s.w_intro(siteName)}
      </p>

      <!-- Features grid -->
      <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:24px">
        ${s.w_features.map(([, title, desc]) => `
          <tr>
            <td style="width:28px;padding:10px 8px 10px 0;vertical-align:top;color:${MUTED};font-weight:600;font-size:14px;line-height:1.6">›</td>
            <td style="padding:10px 0;border-bottom:1px solid ${HAIR}">
              <p style="margin:0;font-size:13px;font-weight:700;color:${INK}">${title}</p>
              <p style="margin:3px 0 0;font-size:12px;color:${MUTED};line-height:1.6">${desc}</p>
            </td>
          </tr>
        `).join("")}
      </table>

      <!-- Getting started steps -->
      <div style="background:${PANEL};border:1px solid ${BORDER};border-radius:12px;padding:18px 20px;margin-bottom:22px">
        <p style="margin:0 0 14px;font-size:11px;font-weight:700;letter-spacing:1px;color:${PRIMARY};text-transform:uppercase">${s.w_gs_label}</p>
        ${[s.w_gs_step1, s.w_gs_step2, s.w_gs_step3].map((step, i) => `
          <div style="display:flex;align-items:flex-start;gap:12px;${i < 2 ? "margin-bottom:12px" : ""}">
            <span style="flex-shrink:0;width:22px;height:22px;background:${PRIMARY};color:#fff;border-radius:50%;font-size:11px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;line-height:1">${i + 1}</span>
            <span style="font-size:12px;color:${TEXT};line-height:1.7;padding-top:2px">${step}</span>
          </div>
        `).join("")}
      </div>

      <!-- Account login info -->
      <div style="background:${PANEL};border:1px solid ${BORDER};border-radius:10px;padding:13px 16px">
        <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase;margin-bottom:5px">${s.w_login_label}</p>
        <p style="margin:0;font-family:${MONO};font-size:13px;color:${INK};font-weight:600">${email}</p>
      </div>
    `)}

    ${actionFooter(`${BASE_URL()}`, s.w_cta)}
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
  const siteName  = p.siteName || "WHOIS";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const isRestricted = p.regStatusType === "prohibited" || p.regStatusType === "reserved";

  // ── Restricted domain email (prohibited / reserved) ──────────────────────
  if (isRestricted) {
    const isProhibited  = p.regStatusType === "prohibited";
    const statusTone: Tone = isProhibited ? "danger" : "warning";
    const statusLabel   = isProhibited ? s.sc_prohibited_label : s.sc_reserved_label;
    const statusDesc    = isProhibited ? s.sc_restricted_prohibited_desc : s.sc_restricted_reserved_desc;

    return emailLayout(`
      ${brandHeader("dark", s.sc_restricted_label, domainBadge(p.domain), s.sc_restricted_sub)}

      ${section(`
        ${card(`
          ${cardBlock(`
            <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${TONES[statusTone].deep};text-transform:uppercase">${s.sc_current_status} · ${statusLabel}</p>
            <p style="margin:6px 0 0;font-size:12px;color:${TEXT};line-height:1.7">${statusDesc}</p>
          `)}
          ${cardBlock(`
            <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${TONES.info.deep};text-transform:uppercase">${s.sc_subscribed}</p>
            <p style="margin:6px 0 0;font-size:13px;font-weight:600;color:${TEXT}">${s.sc_subscribed_desc}</p>
          `)}
        `, { style: "margin-bottom:20px" })}
      `)}

      ${actionFooter(`${BASE_URL()}/${p.domain}`, s.sc_view_domain, { cancelHref: cancelUrl, btnColor: PRIMARY, unsubLabel: s.unsubscribe })}
    `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
  }

  // ── Normal domain email ───────────────────────────────────────────────────
  const expiryStr = fmtEmailDate(p.expirationDate, s);

  const phaseTone: Record<string, Tone> = {
    active:        "success",
    grace:         "warning",
    redemption:    "warning",
    pendingDelete: "danger",
    dropped:       "dark",
  };
  const lc = p.lifecycle;
  const phaseKey = lc?.phase ?? "active";
  const phaseI18n = s.sc_phases[phaseKey] ?? s.sc_phases.active;
  const phaseC = TONES[phaseTone[phaseKey] ?? "success"];

  // Reminder thresholds label: use a generic "N days before" (locale-neutral number)
  const thresholdPills = p.thresholds.map(d =>
    tonePill(`${d}d`, "brand")
  ).join("");

  return emailLayout(`
    ${brandHeader("dark", s.sc_label, domainBadge(p.domain), s.sc_sub)}

    ${section(`
      <!-- Active monitoring banner -->
      <div style="background:${PANEL};border:1px solid ${BORDER};border-left:3px solid ${TONES.success.deep};border-radius:6px;padding:11px 16px;margin-bottom:20px;display:flex;align-items:center;gap:10px">
        <div>
          <p style="margin:0;font-size:12px;font-weight:600;color:${INK}">${s.sc_subscribed}</p>
          <p style="margin:2px 0 0;font-size:11px;color:${MUTED}">${s.sc_subscribed_desc}</p>
        </div>
      </div>

      <!-- Info block -->
      ${card(`
        ${cardHead(s.sc_expiry_date)}
        ${cardBlock(cardValue(expiryStr), { style: "padding-top:14px" })}
        ${cardBlock(`
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${phaseC.deep};text-transform:uppercase">${s.sc_current_status} · ${phaseI18n.label}</p>
          <p style="margin:6px 0 0;font-size:12px;color:${TEXT};line-height:1.7">${phaseI18n.desc}</p>
        `)}
      `, { style: "margin-bottom:20px" })}

      <!-- Thresholds -->
      <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:${INK}">${s.sc_reminder_nodes}</p>
      <div style="margin-bottom:${lc && (lc.hasGrace || lc.hasRedemption || lc.hasPendingDelete) ? "16px" : "0"}">
        ${thresholdPills}
      </div>
      ${lc && (lc.hasGrace || lc.hasRedemption || lc.hasPendingDelete) ? `
      <p style="margin:8px 0 8px;font-size:12px;font-weight:700;color:${INK}">${s.sc_phase_alerts}</p>
      <div>
        ${lc.hasGrace         ? tonePill(s.sc_grace_pill, "warning") : ""}
        ${lc.hasRedemption    ? tonePill(s.sc_redemption_pill, "warning") : ""}
        ${lc.hasPendingDelete ? tonePill(s.sc_pending_pill, "danger") : ""}
      </div>` : ""}
    `)}

    ${actionFooter(`${BASE_URL()}/${p.domain}`, s.sc_view_domain, { cancelHref: cancelUrl, btnColor: PRIMARY, unsubLabel: s.unsubscribe })}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Expiry reminder email
// ──────────────────────────────────────────────────────────────────────────────
export function reminderHtml({
  domain, expirationDate, daysLeft, cancelToken, siteName = "WHOIS",
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
  const tone: Tone = urgent ? "danger" : warn ? "warning" : "dark";
  const accent   = TONES[tone].deep;
  const hdrLabel = urgent ? s.r_urgent_label : s.r_label;
  const btnColor = PRIMARY;

  const bodyText = urgent ? s.r_urgent_body(daysLeft) : s.r_normal_body;

  const extraRows = [
    creationStr ? kvRow(s.r_reg_date, creationStr) : "",
    registrar   ? kvRow(s.r_registrar, registrar)  : "",
    (nameservers && nameservers.length > 0)
      ? kvRow(s.r_nameservers, nameservers.slice(0, 3).map(ns =>
          `<span style="font-family:${MONO};font-size:11px">${ns.toLowerCase()}</span>`
        ).join("<br/>"))
      : "",
  ].filter(Boolean).join("");

  return emailLayout(`
    ${brandHeader(tone, hdrLabel, domainBadge(domain), s.r_sub(daysLeft))}

    ${section(`
      <!-- Large countdown display -->
      <div style="text-align:center;padding:8px 0 18px">
        <p style="margin:0;font-size:72px;font-weight:700;color:${accent};line-height:1;font-family:${MONO}">${daysLeft}</p>
        <p style="margin:4px 0 0;font-size:12px;font-weight:600;color:${MUTED};text-transform:uppercase;letter-spacing:1px">${s.r_expiry_date.toLowerCase()}</p>
      </div>

      ${card(`
        ${cardHead(s.r_expiry_date)}
        ${cardBlock(cardValue(expiryStr), { style: "padding-top:14px" })}
        ${extraRows ? `<div style="padding:4px 18px 8px"><table cellpadding="0" cellspacing="0" style="width:100%">${extraRows}</table></div>` : ""}
      `, { style: "margin-bottom:18px" })}

      <p style="margin:0 0 14px;font-size:13px;color:${TEXT};line-height:1.8">${bodyText}</p>

      <!-- Renewal tip -->
      ${noteBox(s.r_renewal_tip, "dark")}
    `)}

    ${actionFooter(`${BASE_URL()}/${domain}`, s.r_cta, { cancelHref: cancelUrl, btnColor, unsubLabel: s.unsubscribe })}
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
  const siteName  = p.siteName || "WHOIS";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr  = fmtEmailDate(p.expirationDate, s);
  const creationStr = p.creationDate ? fmtEmailDate(p.creationDate, s) : null;

  const cfg = {
    grace: {
      tone: "warning" as Tone,
      label: s.pe_grace_label,
      badge: s.pe_grace_badge,
      body: s.pe_grace_body,
      urgency: s.pe_grace_urgency,
      nextLabel: s.pe_grace_next_label, nextDate: p.graceEnd,
      actions: [s.pe_grace_action1, s.pe_grace_action2, s.pe_grace_action3],
    },
    redemption: {
      tone: "warning" as Tone,
      label: s.pe_redemption_label,
      badge: s.pe_redemption_badge,
      body: s.pe_redemption_body,
      urgency: s.pe_redemption_urgency,
      nextLabel: s.pe_redemption_next_label, nextDate: p.redemptionEnd,
      actions: [s.pe_redemption_action1, s.pe_redemption_action2, s.pe_redemption_action3],
    },
    pendingDelete: {
      tone: "danger" as Tone,
      label: s.pe_pending_label,
      badge: s.pe_pending_badge,
      body: s.pe_pending_body,
      urgency: s.pe_pending_urgency,
      nextLabel: s.pe_pending_next_label, nextDate: p.dropDate,
      actions: [s.pe_pending_action1, s.pe_pending_action2],
    },
  }[p.phase];
  const ct = TONES[cfg.tone];

  return emailLayout(`
    ${brandHeader(cfg.tone, cfg.label, domainBadge(p.domain), s.pe_sub)}

    ${section(`
      ${card(`
        ${cardHead(s.pe_orig_expiry)}
        ${cardBlock(`<p style="margin:0;font-size:16px;font-weight:700;color:${INK};font-family:${MONO}">${expiryStr}</p>`)}
        ${cardBlock(`
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${ct.deep};text-transform:uppercase">${s.pe_current_status} · ${cfg.badge}</p>
        `)}
        ${cfg.nextDate ? cardRow(cfg.nextLabel, cfg.nextDate, { valueStyle: `color:${ct.deep}` }) : ""}
        ${(creationStr || p.registrar) ? `
        <div style="padding:8px 18px 10px;border-top:1px solid ${HAIR}">
          <table cellpadding="0" cellspacing="0" style="width:100%">
            ${creationStr ? kvRow(s.pe_reg_date, creationStr) : ""}
            ${p.registrar  ? kvRow(s.pe_registrar, p.registrar) : ""}
          </table>
        </div>` : ""}
      `, { style: "margin-bottom:18px" })}

      <p style="margin:0 0 14px;font-size:13px;color:${TEXT};line-height:1.8">${cfg.body}</p>

      <!-- Urgency notice -->
      ${noteBox(cfg.urgency, cfg.tone, { bold: true, style: "margin-bottom:16px" })}

      <!-- Action items -->
      ${card(`
        ${cardHead(s.pe_action_label, { style: "background:" + PANEL })}
        ${cfg.actions.map((action: string, i: number) => `
          <div style="padding:10px 18px;border-bottom:${i < cfg.actions.length - 1 ? "1px solid " + HAIR : "none"};display:flex;align-items:flex-start;gap:12px">
            <span style="flex-shrink:0;width:20px;height:20px;border:1px solid ${BORDER};color:${ct.deep};border-radius:50%;font-size:10px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;line-height:1;margin-top:1px">${i + 1}</span>
            <span style="font-size:12px;color:${TEXT};line-height:1.7">${action}</span>
          </div>
        `).join("")}
      `)}
    `)}

    ${actionFooter(`${BASE_URL()}/${p.domain}`, s.pe_cta, { cancelHref: cancelUrl, btnColor: PRIMARY, unsubLabel: s.unsubscribe })}
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
  const siteName  = p.siteName || "WHOIS";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = fmtEmailDate(p.expirationDate, s);
  const urgency   = p.daysToDropDate <= 1 ? s.da_urgency_1 : s.da_urgency_n(p.daysToDropDate);

  return emailLayout(`
    ${brandHeader("brand", s.da_label, domainBadge(p.domain), s.da_sub)}

    ${section(`
      ${card(`
        ${cardHead(s.da_orig_expiry)}
        ${cardBlock(`<p style="margin:0;font-size:16px;font-weight:700;color:${INK};font-family:${MONO}">${expiryStr}</p>`)}
        ${cardBlock(`
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${s.da_avail_date}</p>
          <p style="margin:6px 0 0;font-size:24px;font-weight:700;color:${INK};font-family:${MONO}">${p.dropDate}</p>
        `)}
        ${cardBlock(`<p style="margin:0;font-size:13px;color:${TEXT};line-height:1.7">${s.da_body}</p>`)}
      `, { style: "margin-bottom:18px" })}

      ${noteBox(urgency, "brand", { bold: true, style: "margin-bottom:16px" })}

      <!-- Registration services -->
      <div style="border:1px solid ${BORDER};border-radius:8px;padding:14px 18px">
        <p style="margin:0 0 12px;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${s.pe_action_label}</p>
        ${[s.pe_pending_action1, s.pe_pending_action2].map((action, i) => `
          <div style="${i > 0 ? "margin-top:8px;" : ""}display:flex;align-items:flex-start;gap:10px">
            <span style="color:${MUTED};font-weight:600;font-size:14px;flex-shrink:0">→</span>
            <span style="font-size:12px;color:${TEXT};line-height:1.7">${action}</span>
          </div>
        `).join("")}
      </div>
    `)}

    ${actionFooter(`${BASE_URL()}/${p.domain}`, s.da_cta, { cancelHref: cancelUrl, btnColor: PRIMARY, unsubLabel: s.unsubscribe })}
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
  const siteName  = p.siteName || "WHOIS";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = fmtEmailDate(p.expirationDate, s);
  return emailLayout(`
    ${brandHeader("success", s.dd_label, domainBadge(p.domain), s.dd_sub)}

    ${section(`
      <!-- Available banner -->
      <div style="text-align:center;padding:8px 0 16px">
        <div style="display:inline-block;background:${PANEL};border:1px solid ${BORDER};border-left:3px solid ${TONES.success.deep};border-radius:8px;padding:14px 28px">
          <p style="margin:0;font-size:14px;font-weight:700;color:${TONES.success.deep};letter-spacing:0.12em;text-transform:uppercase">${s.dd_available}</p>
        </div>
      </div>

      ${card(`
        ${cardHead(s.dd_orig_expiry)}
        ${cardBlock(`<p style="margin:0;font-size:16px;font-weight:700;color:${INK};font-family:${MONO}">${expiryStr}</p>`)}
        ${cardBlock(`<p style="margin:0;font-size:12px;color:${TEXT};line-height:1.7">${s.dd_note}</p>`)}
      `, { style: "margin-bottom:18px" })}

      <!-- Registration tip -->
      ${noteBox(s.dd_register_tip, "success", { style: "margin-bottom:16px" })}

      <!-- Registrar links -->
      ${card(`
        ${cardHead(s.dd_cta, { style: "background:" + PANEL })}
        ${[
          { name: "Namecheap", url: `https://www.namecheap.com/domains/registration/results/?domain=${p.domain}` },
          { name: "GoDaddy",   url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${p.domain}` },
          { name: "Porkbun",   url: `https://porkbun.com/checkout/search?q=${p.domain}` },
        ].map(r => `
          <div style="padding:11px 18px;border-bottom:1px solid ${HAIR}">
            <a href="${r.url}" style="font-size:13px;font-weight:600;color:${INK};text-decoration:none">${r.name} →</a>
          </div>
        `).join("")}
        <div style="padding:11px 18px">
          <a href="https://www.namesilo.com/domain/search-domains?query=${encodeURIComponent(p.domain)}" style="font-size:13px;font-weight:600;color:${INK};text-decoration:none">NameSilo →</a>
        </div>
      `)}
    `)}

    ${actionFooter(`${BASE_URL()}/${p.domain}`, s.dd_cta, { cancelHref: cancelUrl, btnColor: PRIMARY, unsubLabel: s.unsubscribe })}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 5c. Domain on hold (clientHold / serverHold)
// ──────────────────────────────────────────────────────────────────────────────
export interface DomainHoldParams {
  domain: string;
  expirationDate: string | null;
  cancelToken: string;
  statuses: string[];
}

export function domainHoldHtml(p: DomainHoldParams & { siteName?: string; locale?: string }): string {
  const siteName  = p.siteName || "WHOIS";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = fmtEmailDate(p.expirationDate, s);

  return emailLayout(`
    ${brandHeader("warning", s.hd_label, domainBadge(p.domain), s.hd_sub)}

    ${section(`
      ${noteBox(s.hd_body(p.domain), "warning", { style: "margin-bottom:18px" })}

      ${card(`
        ${cardHead(s.da_orig_expiry)}
        ${cardBlock(`<p style="margin:0;font-size:16px;font-weight:700;color:${INK};font-family:${MONO}">${expiryStr}</p>`)}
        ${cardBlock(`
          <p style="margin:0;font-size:12px;color:${TEXT};line-height:1.7">
            <strong style="color:${TEXT}">EPP status:</strong> ${p.statuses.join(", ") || "—"}
          </p>
        `, { style: "background:" + PANEL })}
      `, { style: "margin-bottom:18px" })}

      ${noteBox(s.hd_note, "warning")}
    `)}

    ${actionFooter(`${BASE_URL()}/${p.domain}`, s.hd_cta, { cancelHref: cancelUrl, unsubLabel: s.unsubscribe })}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 5d. Reserved domain
// ──────────────────────────────────────────────────────────────────────────────
export interface ReservedDomainParams {
  domain: string;
  expirationDate: string | null;
  cancelToken: string;
}

export function reservedDomainHtml(p: ReservedDomainParams & { siteName?: string; locale?: string }): string {
  const siteName  = p.siteName || "WHOIS";
  const s         = getEmailStrings(p.locale);
  const cancelUrl = `${BASE_URL()}/remind/cancel?token=${p.cancelToken}`;
  const expiryStr = fmtEmailDate(p.expirationDate, s);

  return emailLayout(`
    ${brandHeader("info", s.rv_label, domainBadge(p.domain), s.rv_sub)}

    ${section(`
      ${noteBox(s.rv_body(p.domain), "info", { style: "margin-bottom:18px" })}

      ${card(`
        ${cardHead(s.da_orig_expiry)}
        ${cardBlock(`<p style="margin:0;font-size:16px;font-weight:700;color:${INK};font-family:${MONO}">${expiryStr}</p>`)}
      `, { style: "margin-bottom:18px" })}

      ${noteBox(s.rv_note, "info")}
    `)}

    ${actionFooter(`${BASE_URL()}/${p.domain}`, s.rv_cta, { cancelHref: cancelUrl, btnColor: "#0369a1", unsubLabel: s.unsubscribe })}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. Password reset email
// ──────────────────────────────────────────────────────────────────────────────
export function passwordResetHtml({ resetUrl, siteName = "WHOIS", locale }: {
  resetUrl: string; siteName?: string; locale?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${brandHeader("dark", s.pr_label, s.pr_title)}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:${TEXT};line-height:1.8">${s.pr_body}</p>

      ${ctaBtn(resetUrl, s.pr_cta, PRIMARY)}

      ${noteBox(`<span style="font-size:11px;color:${MUTED};line-height:1.7">${s.pr_link_note}<br/><a href="${resetUrl}" style="color:${PRIMARY};font-size:11px;word-break:break-all">${resetUrl}</a></span>`, "dark", { style: "margin:22px 0 0" })}

      <p style="margin:16px 0 8px;font-size:11px;color:${MUTED};line-height:1.7">${s.pr_security}</p>

      <!-- Didn't request section -->
      <div style="border-top:1px solid ${HAIR};margin-top:18px;padding-top:16px">
        <p style="margin:0 0 4px;font-size:12px;font-weight:700;color:${TEXT}">${s.pr_not_you}</p>
        <p style="margin:0;font-size:12px;color:${MUTED};line-height:1.7">${s.pr_not_you_body}</p>
      </div>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. Admin test / notification email  (admin-only — stays in English/Chinese)
// ──────────────────────────────────────────────────────────────────────────────
export function adminNotifyHtml({ subject, body, siteName = "WHOIS" }: {
  subject: string; body: string; siteName?: string;
}): string {
  return emailLayout(`
    ${brandHeader("dark", "Admin Notification", subject)}
    ${section(`<p style="margin:0;font-size:13px;color:${TEXT};line-height:1.8">${body}</p>`)}
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 7b. Domain-drop snipe notifications (admin-only — fixed Chinese copy)
// ──────────────────────────────────────────────────────────────────────────────
export function snipeNotifyHtml(tone: "success" | "danger" | "warning" | "info", p: {
  title: string;
  domain: string;
  lines: Array<[string, string]>;
  siteName?: string;
}): string {
  const t = TONES[tone];
  const rows = p.lines.map(([label, value]) =>
    kvRow(label, label === "域名" || label === "原因" ? domainBadge(value) : value)
  );
  return emailLayout(`
    ${brandHeader(tone, "Snipe Alert", p.title, "", { titleStyle: `color:${t.deep}` })}
    ${section(`
      ${noteBox(`目标域名 <span style="font-family:${MONO};font-weight:700">${p.domain}</span>`, tone, { html: true })}
      <table cellpadding="0" cellspacing="0" style="width:100%;margin-top:6px">
        ${rows.join("")}
      </table>
    `)}
  `, p.siteName ?? "WHOIS");
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. User preorder sniping notifications (user-facing — fixed Chinese copy).
// Reuses the snipe admin layout; tone + amount emphasise the only material
// changes for the user (charge / refund / frozen / needed).
// ──────────────────────────────────────────────────────────────────────────────
export function snipeArmedHtml(p: {
  domain: string;
  serviceCents: number;
  siteName?: string;
}): string {
  return snipeNotifyHtml("success", {
    title: "抢注预定已生效（冻结完成）",
    domain: p.domain,
    lines: [
      ["状态", "已进入竞速阶段，将在域名释放时自动抢注"],
      ["服务价", `¥ ${(p.serviceCents / 100).toFixed(2)}（已冻结）`],
      ["说明", "冻结金额仅在抢注成功时扣费；未抢到将自动解冻退还"],
    ],
    siteName: p.siteName,
  });
}

export function snipeSettledHtml(p: {
  domain: string;
  serviceCents: number;
  opeId: string | undefined;
  siteName?: string;
}): string {
  return snipeNotifyHtml("success", {
    title: "域名抢注成功",
    domain: p.domain,
    lines: [
      ["状态", "已注册成功，冻结金额已作为实际扣费"],
      ["扣费金额", `¥ ${(p.serviceCents / 100).toFixed(2)}+`],
      ["操作号", p.opeId ?? "—"],
      ["提示", "域名已注册至平台账户，交付方式请留意站内后续通知"],
    ],
    siteName: p.siteName,
  });
}

export function snipeReleasedHtml(p: {
  domain: string;
  releasedCents: number;
  siteName?: string;
}): string {
  return snipeNotifyHtml("info", {
    title: "抢注未成功，冻结已解冻",
    domain: p.domain,
    lines: [
      ["状态", "本次未抢到该域名，预定占坑已释放"],
      ["解冻金额", `¥ ${(p.releasedCents / 100).toFixed(2)} 已退回余额`],
      ["后续", "如需再次预定该域名，可重新提交"],
    ],
    siteName: p.siteName,
  });
}

export function snipeInsufficientHtml(p: {
  domain: string;
  serviceCents: number;
  balanceCents: number;
  siteName?: string;
}): string {
  const needed = p.serviceCents - p.balanceCents;
  return snipeNotifyHtml("warning", {
    title: "抢注预定额度不足，需充值",
    domain: p.domain,
    lines: [
      ["状态", "预定额度不足以进入竞速，充值到账后将自动启用"],
      ["服务价", `¥ ${(p.serviceCents / 100).toFixed(2)}`],
      ["当前余额", `¥ ${(p.balanceCents / 100).toFixed(2)}`],
      ["缺口", `¥ ${(Math.max(0, needed) / 100).toFixed(2)}`],
    ],
    siteName: p.siteName,
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. Feedback notification email (sent to admin — stays in Chinese)
// ──────────────────────────────────────────────────────────────────────────────
export function feedbackHtml({
  query, queryType, issueLabels, description, email, ip, ts, siteName = "WHOIS",
}: {
  query: string; queryType: string; issueLabels: string; description?: string;
  email?: string; ip: string; ts: string; siteName?: string;
}): string {
  const rows = [
    kvRow("查询目标", `<span style="font-family:${MONO}">${query}</span>`),
    kvRow("查询类型", queryType),
    kvRow("问题类型", `<span style="color:${TONES.danger.fg}">${issueLabels}</span>`),
    ...(description ? [kvRow("补充说明", `<span style="white-space:pre-wrap">${description}</span>`)] : []),
    ...(email ? [kvRow("联系邮箱", `<a href="mailto:${email}" style="color:${PRIMARY}">${email}</a>`)] : []),
  ];

  return emailLayout(`
    ${brandHeader("dark", "用户反馈", query, ts + "（北京时间）")}

    ${section(`
      <table cellpadding="0" cellspacing="0" style="width:100%">
        ${rows.join("")}
      </table>
    `)}

    ${divider()}
    <div style="padding:14px 32px;background:${PANEL}">
      <p style="margin:0;font-size:11px;color:${MUTED}">IP：${ip} · 来源：${siteName} 反馈系统</p>
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
  const siteName = p.siteName || "WHOIS";
  const tone: Tone = p.score >= 80 ? "danger" : p.score >= 60 ? "warning" : "dark";
  const t = TONES[tone];
  const ALERT_COLOR = t.deep;
  const LOOKUP_URL  = `${BASE_URL()}/${p.domain}`;

  const labelRow = (l: string, v: string) =>
    `<tr><td style="padding:8px 0;font-size:12px;color:${MUTED};font-weight:500;width:90px;vertical-align:top;border-bottom:1px solid ${HAIR}">${l}</td><td style="padding:8px 0;font-size:13px;color:${INK};font-weight:600;border-bottom:1px solid ${HAIR}">${v}</td></tr>`;

  const scoreBar = (label: string, val: number, max: number) => {
    const pct = Math.round((val / max) * 100);
    return `<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:11px;color:${TEXT}">${label}</span>
        <span style="font-size:11px;font-weight:600;color:${MUTED}">${val}/${max}</span>
      </div>
      <div style="height:4px;background:${HAIR};border-radius:999px;overflow:hidden">
        <div style="height:4px;width:${pct}%;background:${INK};border-radius:999px"></div>
      </div>
    </div>`;
  };

  return emailLayout(`
    ${brandHeader(tone, p.isAlertKeyword ? "特殊关键词可用告警" : "高价值域名可用告警", p.domain,
      "该域名当前未被注册，请及时评估并决定是否注册",
      { titleStyle: `font-size:26px;font-weight:700;font-family:${MONO};letter-spacing:-0.5px` })}

    ${section(`
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap">
        <div style="border:1px solid ${BORDER};border-left:3px solid ${ALERT_COLOR};border-radius:8px;padding:14px 20px;text-align:center;min-width:90px">
          <p style="margin:0;font-size:32px;font-weight:700;color:${ALERT_COLOR};line-height:1;font-family:${MONO}">${p.score}</p>
          <p style="margin:4px 0 0;font-size:10px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">价值评分</p>
        </div>
        <div>
          <div style="display:inline-block;border:1px solid ${BORDER};color:${ALERT_COLOR};padding:3px 12px;border-radius:999px;font-size:13px;font-weight:600;margin-bottom:8px">
            ${p.tier}价值
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${p.reasons.map(r => pill(r)).join("")}
            ${p.isAlertKeyword ? pill("特殊关键词") : ""}
            ${p.isNumericOnly  ? pill("纯数字") : ""}
            ${p.hotPrefix      ? pill(`热门前缀: ${p.hotPrefix.prefix}`) : ""}
          </div>
        </div>
      </div>

      ${p.hotPrefix ? `<div style="border:1px solid ${BORDER};border-radius:8px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 8px;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">热门前缀监控命中</p>
        <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
          <span style="font-family:${MONO};font-size:16px;font-weight:700;color:${INK};border:1px solid ${BORDER};background:${PANEL};padding:4px 12px;border-radius:6px">${p.hotPrefix.prefix}</span>
          <span style="font-size:12px;color:${MUTED}">分类：${p.hotPrefix.category} &nbsp;·&nbsp; 权重：${p.hotPrefix.weight} &nbsp;·&nbsp; 匹配：${p.hotPrefix.matchType === "exact" ? "精确" : "前缀"}</span>
        </div>
        ${p.hotPrefix.notes ? `<p style="margin:8px 0 0;font-size:12px;color:${TEXT}">${p.hotPrefix.notes}</p>` : ""}
        ${p.hotPrefix.saleExamples ? `<p style="margin:6px 0 0;font-size:11px;color:${MUTED}">参考成交：${p.hotPrefix.saleExamples}</p>` : ""}
      </div>` : ""}

      <div style="border:1px solid ${BORDER};border-radius:8px;padding:16px;margin-bottom:20px">
        <p style="margin:0 0 12px;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">评分明细</p>
        ${scoreBar("名称长度", p.breakdown.lengthScore, 30)}
        ${scoreBar("后缀价值", p.breakdown.tldScore, 20)}
        ${scoreBar("热词匹配", p.breakdown.keywordScore, 25)}
        ${scoreBar("特征加分", p.breakdown.patternScore, 15)}
      </div>

      ${p.aiSummary ? `${noteBox(`
        <p style="margin:0 0 8px;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">AI 快速评估</p>
        <p style="margin:0;font-size:13px;color:${TEXT};line-height:1.6">${p.aiSummary}</p>
      `, "dark", { html: true, style: "margin-bottom:20px" })}` : ""}

      <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:20px">
        ${labelRow("域名", `<span style="font-family:${MONO};font-size:15px;color:${INK}">${p.domain}</span>`)}
        ${labelRow("状态", `<span style="color:${INK};font-weight:600">可注册（未被注册）</span>`)}
        ${p.checkedBy ? labelRow("查询者", p.checkedBy) : ""}
        ${labelRow("检测时间", new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }) + "（北京时间）")}
      </table>
    `)}

    ${divider()}
    <div style="padding:20px 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
      ${ctaBtn(LOOKUP_URL, "立即查看域名详情")}
      <a href="https://www.namesilo.com/domain/search-domains?query=${encodeURIComponent(p.domain)}"
         style="font-size:12px;color:${MUTED};text-decoration:underline;text-underline-offset:3px">
        前往 NameSilo 注册 →
      </a>
    </div>
  `, siteName);
}

// ──────────────────────────────────────────────────────────────────────────────
// 10. Stamp DNS verification timeout (sent to user)
// ──────────────────────────────────────────────────────────────────────────────
export function stampVerifyTimeoutHtml({
  domain, fileContent, verifyUrl, siteName = "WHOIS", locale,
}: {
  domain: string; fileContent: string; verifyUrl: string; siteName?: string; locale?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${brandHeader("danger", s.sv_label, domainBadge(domain), s.sv_sub)}

    ${section(`
      <p style="margin:0 0 18px;font-size:13px;color:${TEXT};line-height:1.8">${s.sv_intro}</p>

      ${card(`
        ${cardHead(s.sv_step1_title)}
        ${cardBlock(`
          <p style="margin:0;font-size:13px;color:${INK}">${s.sv_step1_body}</p>
          <p style="margin:6px 0 0;font-family:${MONO};font-size:12px;color:${PRIMARY};background:${PANEL};padding:8px 12px;border-radius:6px;word-break:break-all">
            /.well-known/next-whois-verify.txt
          </p>
        `)}
        ${cardBlock(`
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${s.sv_step2_title}</p>
          <p style="margin:8px 0 0;font-family:${MONO};font-size:12px;color:${INK};background:${BG};padding:10px 14px;border-radius:6px;word-break:break-all">${fileContent}</p>
        `, { style: "background:" + PANEL })}
        ${cardBlock(`
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${s.sv_step3_title}</p>
          <p style="margin:6px 0 0;font-size:12px;color:${TEXT}">${s.sv_step3_body}</p>
        `)}
      `, { style: "margin-bottom:18px" })}

      ${ctaBtn(verifyUrl, s.sv_cta)}
      <p style="margin:16px 0 0;font-size:11px;color:${MUTED}">${s.sv_retry}</p>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 11. Password changed notification
// ──────────────────────────────────────────────────────────────────────────────
export function passwordChangedHtml({ siteName = "WHOIS", locale, changedAt, name, email }: {
  siteName?: string; locale?: string; changedAt?: string; name?: string | null; email?: string;
}): string {
  const s      = getEmailStrings(locale);
  const baseUrl = BASE_URL();
  const ts     = changedAt || new Date().toLocaleString(s.date_locale, { dateStyle: "medium", timeStyle: "short" });
  return emailLayout(`
    ${brandHeader("danger", s.pc_label, s.pc_title, s.pc_sub)}

    ${section(`
      <p style="margin:0 0 20px;font-size:13px;color:${TEXT};line-height:1.8">${s.pc_body}</p>

      <!-- Change details -->
      ${card(`
        ${cardBlock(`
          <p style="margin:0;font-size:11px;font-weight:600;letter-spacing:1px;color:${MUTED};text-transform:uppercase">${s.pc_time_label}</p>
          <p style="margin:5px 0 0;font-size:14px;font-weight:700;color:${INK};font-family:${MONO}">${ts}</p>
        `)}
        ${cardBlock(`<p style="margin:0;font-size:12px;color:${TEXT}">${s.pc_sub}</p>`)}
      `, { style: "margin-bottom:18px" })}

      ${ctaBtn(baseUrl + "/account", s.pc_cta)}

      <!-- Didn't change section -->
      ${noteBox(`
        <p style="margin:0 0 6px;font-size:12px;font-weight:700;color:${TONES.danger.deep}">${s.pc_not_you}</p>
        <p style="margin:0;font-size:12px;color:${TEXT};line-height:1.7">${s.pc_not_you_body(siteName)}</p>
      `, "danger", { html: true, style: "margin-top:18px" })}
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 12. Email verification code
// ──────────────────────────────────────────────────────────────────────────────
export function verifyCodeHtml({ code, siteName = "WHOIS", locale, email }: {
  code: string; siteName?: string; locale?: string; email?: string;
}): string {
  const s = getEmailStrings(locale);
  return emailLayout(`
    ${brandHeader("dark", s.vc_label, s.vc_title, s.vc_sub)}

    ${section(`
      <p style="margin:0 0 22px;font-size:13px;color:${TEXT};line-height:1.8">${s.vc_body}</p>

      <!-- Large code display -->
      ${codeBox(code)}

      <!-- Expiry info -->
      ${noteBox(s.vc_expires, "warning", { style: "margin:22px 0 14px" })}

      <p style="margin:0;font-size:11px;color:${MUTED};line-height:1.7;text-align:center">${s.vc_security}</p>
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 13. Admin broadcast message (admin → all users)
// ──────────────────────────────────────────────────────────────────────────────
export function adminBroadcastHtml({ subject, body, bodyHtml, siteName = "WHOIS", locale }: {
  subject: string; body?: string; bodyHtml?: string; siteName?: string; locale?: string;
}): string {
  const s       = getEmailStrings(locale);
  const content = bodyHtml || (body ? `<p style="margin:0;font-size:13px;color:${TEXT};line-height:1.9;white-space:pre-wrap">${body}</p>` : "");
  return emailLayout(`
    ${brandHeader("dark", s.ab_label, subject)}

    ${section(content)}

    ${actionFooter(BASE_URL(), siteName, { btnColor: PRIMARY })}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// 14. Payment confirmation
// ──────────────────────────────────────────────────────────────────────────────
export function paymentConfirmHtml({ plan, planName, expiresAt, amount, currency = "USD", orderId, siteName = "WHOIS", locale, name, email }: {
  plan?: string; planName?: string; expiresAt?: string | null; amount?: number | string | null;
  currency?: string; orderId?: string; siteName?: string; locale?: string; name?: string | null; email?: string;
}): string {
  const s        = getEmailStrings(locale);
  const planDisp = planName || plan || "—";
  const amtStr   = amount != null ? String(amount) : null;
  return emailLayout(`
    ${brandHeader("success", s.pay_label, s.pay_title)}

    ${section(`
      <!-- Success banner -->
      <div style="text-align:center;padding:8px 0 20px">
        <div style="display:inline-block;background:${PANEL};border:1px solid ${BORDER};border-left:3px solid ${TONES.success.deep};border-radius:8px;padding:10px 22px">
          <p style="margin:0;font-size:13px;font-weight:700;color:${TONES.success.deep};letter-spacing:0.12em;text-transform:uppercase">${s.pay_sub}</p>
        </div>
      </div>

      <p style="margin:0 0 20px;font-size:13px;color:${TEXT};line-height:1.8;text-align:center">${s.pay_body}</p>

      <!-- Plan details -->
      ${card(`
        ${cardRow(s.pay_plan_label, planDisp, { valueStyle: "font-size:16px" })}
        ${orderId ? cardRow("Order ID", orderId, { valueStyle: `font-size:12px;font-weight:600;color:${TEXT};font-family:${MONO}` }) : ""}
        ${expiresAt ? cardRow(s.pay_expires_label, expiresAt, { valueStyle: `font-size:14px;font-family:${MONO}` }) : ""}
        ${amtStr ? cardRow(s.pay_amount_label, `${currency} ${amtStr}`, { valueStyle: `font-size:18px;font-weight:700` }) : ""}
      `, { style: "margin-bottom:18px" })}

      <p style="margin:0 0 18px;font-size:11px;color:${MUTED};line-height:1.7">${s.pay_receipt}</p>

      ${ctaBtn(BASE_URL() + "/account", s.pay_cta)}
    `)}
  `, siteName, { langCode: s.date_locale, autoSentText: s.auto_sent(siteName) });
}

// ──────────────────────────────────────────────────────────────────────────────
// Membership renewal reminder
// ──────────────────────────────────────────────────────────────────────────────
export function membershipRenewHtml({ daysLeft, expiresAt, siteName = "WHOIS", locale }: {
  daysLeft: number;
  expiresAt: string | null;
  siteName?: string;
  locale?: string;
}): string {
  const s = getEmailStrings(locale);
  const urgency = daysLeft <= 0
    ? s.mr_expired
    : daysLeft <= 1
      ? s.mr_days_1
      : s.mr_days_7;
  const tone: Tone = daysLeft <= 1 ? "danger" : "warning";
  const accent = TONES[tone].deep;

  return emailLayout(`
    ${brandHeader(tone, s.mr_label, s.mr_sub)}

    ${section(`
      ${noteBox(s.mr_body, tone, { style: "margin-bottom:18px" })}

      ${card(`
        ${cardRow(s.pay_expires_label, expiresAt ? fmtEmailDate(expiresAt, s) : "—")}
        ${cardBlock(`<p style="margin:0;font-size:13px;font-weight:600;color:${accent}">${urgency}</p>`)}
      `, { style: "margin-bottom:18px" })}
    `)}

    ${actionFooter(BASE_URL() + "/payment/checkout", s.mr_cta, { cancelHref: BASE_URL() + "/dashboard", unsubLabel: s.unsubscribe })}
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

// TTL cache for SMTP / Resend provider settings. These are read for every
// outbound email; without a cache a reminder batch of N messages pays N DB
// round-trips per provider setting. Changes made in the admin panel propagate
// within one TTL window.
let _smtpCache: SmtpConfig | null | undefined;
let _smtpCacheAt = 0;
const SMTP_TTL = 60_000;

let _resendCache: { key: string; from: string } | undefined;
let _resendCacheAt = 0;
const RESEND_TTL = 60_000;

async function getSmtpConfig(): Promise<SmtpConfig | null> {
  if (_smtpCache !== undefined && Date.now() - _smtpCacheAt < SMTP_TTL) return _smtpCache;
  try {
    const rows = await import("@/lib/db-query").then(m =>
      m.many<{ key: string; value: string }>(
        `SELECT key, value FROM site_settings WHERE key IN
         ('smtp_enabled','smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from','smtp_secure')`
      )
    );
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    if (map.smtp_enabled !== "1") { _smtpCache = null; return null; }
    if (!map.smtp_host || !map.smtp_user || !map.smtp_pass) { _smtpCache = null; return null; }
    _smtpCache = {
      host: map.smtp_host,
      port: parseInt(map.smtp_port || "465"),
      user: map.smtp_user,
      pass: map.smtp_pass,
      from: map.smtp_from || map.smtp_user,
      secure: map.smtp_secure || "ssl",
    };
  } catch {
    _smtpCache = null;
  } finally {
    _smtpCacheAt = Date.now();
  }
  return _smtpCache;
}

function withSenderName(email: string, name: string): string {
  if (!email || email.includes("<")) return email;
  const safeName = name.replace(/[<>"]/g, "").trim() || "WHOIS";
  return `${safeName} <${email}>`;
}

async function sendViaSMTP(smtp: SmtpConfig, to: string, subject: string, html: string) {
  const siteLabel  = await getSiteLabel();
  const nodemailer = await import("nodemailer");
  const transporter = nodemailer.default.createTransport({
    host: smtp.host,
    port: smtp.port,
    // ssl: port 465 — encrypted from the start
    // starttls: port 587/25 — upgrade after greeting
    // none: plain-text (internal SMTP relay, no TLS at all)
    secure:       smtp.secure === "ssl",
    requireTLS:   smtp.secure === "starttls",
    ignoreTLS:    smtp.secure === "none",
    auth: { user: smtp.user, pass: smtp.pass },
    tls: { rejectUnauthorized: false },
    // Prevent indefinite hangs when the SMTP host is unreachable or slow
    connectionTimeout: 30_000,  // 30s to establish TCP connection
    greetingTimeout:   15_000,  // 15s to receive SMTP banner after connecting
    socketTimeout:     30_000,  // 30s of inactivity during DATA transfer
  });
  await transporter.sendMail({ from: withSenderName(smtp.from, siteLabel), to, subject, html });
}

async function getResendConfig(): Promise<{ key: string; from: string }> {
  if (_resendCache && Date.now() - _resendCacheAt < RESEND_TTL) return _resendCache;
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
  _resendCache = { key: resendKey, from: configuredFrom };
  _resendCacheAt = Date.now();
  return _resendCache;
}

async function sendViaResend(to: string, subject: string, html: string): Promise<void> {
  const { key: resendKey, from: configuredFrom } = await getResendConfig();
  if (!resendKey) {
    throw new Error("邮件服务未配置：请在管理后台的「邮件」设置中配置 SMTP 或填写 Resend API Key，否则无法发送邮件。");
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
      logger.warn(`[sendEmail] Domain not verified for "${from}", retrying with ${RESEND_FALLBACK_FROM}`);
      continue;
    }
    lastErr = `Resend ${resp.status}: ${body.slice(0, 200)}`;
    logger.error("[sendEmail] Resend error:", resp.status, body);
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
 *
 * Also accepts `htmlFn(baseUrl)` instead of `html` — the function is called
 * AFTER the site URL is resolved from the DB, so all template links use the
 * admin-configured `og_url` rather than the NEXT_PUBLIC_BASE_URL env var.
 */
export async function sendEmail({
  to, subject, html, htmlFn,
}: { to: string; subject: string; html?: string; htmlFn?: (baseUrl: string) => string }) {
  // Resolve base URL from DB (og_url setting) so email template links are correct.
  // This also warms the _urlCache for the synchronous BASE_URL() used by other templates.
  const baseUrl = await getSiteBaseUrl();
  const renderedHtml = htmlFn ? htmlFn(baseUrl) : (html ?? "");
  try {
    await sendEmailDirect(to, subject, renderedHtml);
  } catch (err: any) {
    logger.error(`[sendEmail] Failed — queuing for retry → ${to}: ${err.message}`);
    const { enqueueEmail } = await import("@/lib/email-queue");
    await enqueueEmail(to, subject, renderedHtml).catch((qErr: any) => {
      // Both direct send AND queue fallback failed — surface loudly so the
      // email is never silently lost.
      logger.error(
        `[sendEmail] CRITICAL: direct send and queue enqueue both failed → ${to} "${subject}":`,
        `send=${err.message}`,
        `enqueue=${qErr?.message ?? qErr}`,
      );
      throw new Error(`Email delivery failed permanently: ${err.message}`);
    });
  }
}
