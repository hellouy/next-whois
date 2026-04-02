/**
 * POST /api/admin/test-email
 *
 * Body:
 *   { to?: string, template?: string }
 *
 * template values:
 *   "all"                — send every template (default)
 *   "welcome"            — welcome email
 *   "subscription"       — subscription confirmed
 *   "reminder"           — domain expiry reminder
 *   "phase_grace"        — grace period phase event
 *   "phase_redemption"   — redemption phase event
 *   "phase_pending"      — pending-delete phase event
 *   "drop_approaching"   — drop approaching
 *   "dropped"            — domain dropped / available
 *   "password_reset"     — password reset link
 *   "password_changed"   — password changed notification
 *   "verify_code"        — email verification code
 *   "admin_notify"       — admin notification
 *   "admin_broadcast"    — admin broadcast
 *   "payment_confirm"    — payment confirmation
 *   "high_value"         — high-value domain alert
 *   "stamp_timeout"      — stamp verify timeout
 *   "feedback"           — feedback receipt
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import {
  sendEmail,
  getSiteLabel,
  welcomeHtml,
  subscriptionConfirmHtml,
  reminderHtml,
  phaseEventHtml,
  dropApproachingHtml,
  domainDroppedHtml,
  passwordResetHtml,
  passwordChangedHtml,
  verifyCodeHtml,
  adminNotifyHtml,
  adminBroadcastHtml,
  paymentConfirmHtml,
  highValueAlertHtml,
  stampVerifyTimeoutHtml,
  feedbackHtml,
} from "@/lib/email";

// ── sample data used for all preview emails ────────────────────────────────

const SAMPLE_DOMAIN  = "example.com";
const SAMPLE_EMAIL   = "admin@example.com";
const SAMPLE_NAME    = "管理员";
const SAMPLE_LOCALE  = "zh";

function buildTemplates(siteName: string): { key: string; subject: string; html: string }[] {
  const now      = new Date();
  const expDate  = new Date(now.getTime() + 30 * 86400 * 1000);
  const dropDate = new Date(now.getTime() + 7  * 86400 * 1000);

  return [
    {
      key: "welcome",
      subject: `[预览] 欢迎邮件 — ${siteName}`,
      html: welcomeHtml({ name: SAMPLE_NAME, email: SAMPLE_EMAIL, siteName, locale: SAMPLE_LOCALE }),
    },
    {
      key: "subscription",
      subject: `[预览] 订阅确认 — ${siteName}`,
      html: subscriptionConfirmHtml({
        domain: SAMPLE_DOMAIN,
        expirationDate: expDate.toLocaleDateString("zh-CN"),
        cancelToken: "preview-cancel-token",
        thresholds: [7, 14, 30],
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "reminder",
      subject: `[预览] 到期提醒 — ${siteName}`,
      html: reminderHtml({
        domain: SAMPLE_DOMAIN,
        expirationDate: expDate.toLocaleDateString("zh-CN"),
        daysLeft: 30,
        cancelToken: "preview-cancel-token",
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "phase_grace",
      subject: `[预览] 宽限期通知 — ${siteName}`,
      html: phaseEventHtml({
        domain: SAMPLE_DOMAIN,
        phase: "grace",
        expirationDate: now.toLocaleDateString("zh-CN"),
        graceEnd: new Date(now.getTime() + 45 * 86400 * 1000).toLocaleDateString("zh-CN"),
        cancelToken: "preview-cancel-token",
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "phase_redemption",
      subject: `[预览] 赎回期通知 — ${siteName}`,
      html: phaseEventHtml({
        domain: SAMPLE_DOMAIN,
        phase: "redemption",
        expirationDate: now.toLocaleDateString("zh-CN"),
        redemptionEnd: new Date(now.getTime() + 30 * 86400 * 1000).toLocaleDateString("zh-CN"),
        cancelToken: "preview-cancel-token",
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "phase_pending",
      subject: `[预览] 待删除期通知 — ${siteName}`,
      html: phaseEventHtml({
        domain: SAMPLE_DOMAIN,
        phase: "pendingDelete",
        expirationDate: now.toLocaleDateString("zh-CN"),
        dropDate: new Date(now.getTime() + 5 * 86400 * 1000).toLocaleDateString("zh-CN"),
        cancelToken: "preview-cancel-token",
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "drop_approaching",
      subject: `[预览] 域名即将可抢注 — ${siteName}`,
      html: dropApproachingHtml({
        domain: SAMPLE_DOMAIN,
        dropAt: dropDate.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }),
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "dropped",
      subject: `[预览] 域名已可抢注 — ${siteName}`,
      html: domainDroppedHtml({
        domain: SAMPLE_DOMAIN,
        droppedAt: now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }),
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "password_reset",
      subject: `[预览] 密码重置 — ${siteName}`,
      html: passwordResetHtml({
        resetUrl: "https://example.com/reset-password?token=preview_token_abc123",
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "password_changed",
      subject: `[预览] 密码已修改 — ${siteName}`,
      html: passwordChangedHtml({
        name: SAMPLE_NAME,
        email: SAMPLE_EMAIL,
        changedAt: now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }),
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "verify_code",
      subject: `[预览] 邮箱验证码 — ${siteName}`,
      html: verifyCodeHtml({
        code: "847291",
        email: SAMPLE_EMAIL,
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "admin_notify",
      subject: `[预览] 管理员通知 — ${siteName}`,
      html: adminNotifyHtml({
        subject: "系统通知预览",
        body: `这是一封管理员通知的预览邮件。<br><br>
          <strong>系统：</strong>${siteName}<br>
          <strong>时间：</strong>${now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}<br><br>
          邮件系统工作正常，所有模版已正确配置。`,
        siteName,
      }),
    },
    {
      key: "admin_broadcast",
      subject: `[预览] 管理员广播 — ${siteName}`,
      html: adminBroadcastHtml({
        subject: "平台公告预览",
        bodyHtml: `<p style="margin:0;font-size:14px;color:#1e293b;line-height:1.8">
          亲爱的用户，<br><br>
          我们将于近期进行系统维护升级，届时部分功能可能暂时不可用。<br><br>
          感谢您的理解与支持！<br><br>
          — ${siteName} 团队
        </p>`,
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "payment_confirm",
      subject: `[预览] 支付确认 — ${siteName}`,
      html: paymentConfirmHtml({
        planName: "高级会员 · 年度套餐",
        amount: 99,
        currency: "CNY",
        orderId: "ORD-2026-0401-001234",
        expiresAt: new Date(now.getTime() + 365 * 86400 * 1000).toLocaleDateString("zh-CN"),
        name: SAMPLE_NAME,
        email: SAMPLE_EMAIL,
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "high_value",
      subject: `[预览] 高价值域名提醒 — ${siteName}`,
      html: highValueAlertHtml({
        domain: "premium.ai",
        score: 88,
        tier: "极高",
        reasons: ["短域名", "热门后缀", "AI关键词"],
        isAlertKeyword: false,
        isNumericOnly: false,
        hotPrefix: null,
        aiSummary: "premium.ai 是一个极具价值的高端 AI 领域域名，建议优先注册。",
        checkedBy: SAMPLE_EMAIL,
        breakdown: { lengthScore: 28, tldScore: 20, keywordScore: 25, patternScore: 15 },
        siteName,
      }),
    },
    {
      key: "stamp_timeout",
      subject: `[预览] 时间戳验证超时 — ${siteName}`,
      html: stampVerifyTimeoutHtml({
        domain: SAMPLE_DOMAIN,
        fileContent: `next-whois-verify:preview-stamp-abc123`,
        verifyUrl: `${process.env.NEXTAUTH_URL || "https://example.com"}/stamp/verify?id=preview`,
        siteName,
        locale: SAMPLE_LOCALE,
      }),
    },
    {
      key: "feedback",
      subject: `[预览] 用户反馈 — ${siteName}`,
      html: feedbackHtml({
        query: SAMPLE_DOMAIN,
        queryType: "WHOIS",
        issueLabels: "数据不准确",
        description: "查询结果显示的到期时间不正确，实际应为2027年。",
        email: SAMPLE_EMAIL,
        ip: "192.168.1.1",
        ts: now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" }),
        siteName,
      }),
    },
  ];
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await requireAdmin(req, res);
  if (!session) return;

  const to       = (req.body?.to as string | undefined) || session.user?.email || "";
  const template = (req.body?.template as string | undefined) || "all";

  if (!to) return res.status(400).json({ error: "No recipient email specified" });

  const siteName  = await getSiteLabel().catch(() => "X.RW");
  const templates = buildTemplates(siteName);

  const targets = template === "all"
    ? templates
    : templates.filter(t => t.key === template);

  if (targets.length === 0) {
    return res.status(400).json({
      error: `Unknown template "${template}"`,
      available: templates.map(t => t.key),
    });
  }

  const results: { key: string; subject: string; ok: boolean; error?: string }[] = [];

  for (const t of targets) {
    try {
      await sendEmail({ to, subject: t.subject, html: t.html });
      results.push({ key: t.key, subject: t.subject, ok: true });
      console.log(`[test-email] Sent "${t.key}" → ${to}`);
    } catch (err: any) {
      results.push({ key: t.key, subject: t.subject, ok: false, error: err.message });
      console.error(`[test-email] Failed "${t.key}" → ${to}:`, err.message);
    }
  }

  const sentCount  = results.filter(r => r.ok).length;
  const failCount  = results.filter(r => !r.ok).length;

  return res.status(200).json({
    ok: failCount === 0,
    to,
    template,
    total: results.length,
    sent: sentCount,
    failed: failCount,
    results,
  });
}
