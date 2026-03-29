import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { sendEmail, adminNotifyHtml, getSiteLabel } from "@/lib/email";
import { many } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await requireAdmin(req, res);
  if (!session) return;

  const to = (req.body?.to as string) || session.user?.email;
  if (!to) return res.status(400).json({ error: "No recipient email" });

  const siteName = await getSiteLabel().catch(() => "X.RW");

  // Detect which provider is active
  const rows = await many<{ key: string; value: string }>(
    `SELECT key, value FROM site_settings WHERE key IN ('smtp_enabled','smtp_host','smtp_user','smtp_from')`
  ).catch(() => [] as { key: string; value: string }[]);
  const cfg: Record<string, string> = {};
  for (const r of rows) cfg[r.key] = r.value;

  const smtpActive = !!(cfg.smtp_enabled && cfg.smtp_host && cfg.smtp_user);
  const resendRows = await many<{ key: string; value: string }>(
    `SELECT key, value FROM site_settings WHERE key IN ('resend_api_key','resend_from_email')`
  ).catch(() => [] as { key: string; value: string }[]);
  const rcfg: Record<string, string> = {};
  for (const r of resendRows) rcfg[r.key] = r.value;
  const resendKey = rcfg.resend_api_key || process.env.RESEND_API_KEY || "";

  if (!smtpActive && !resendKey) {
    return res.status(503).json({ error: "未配置邮件发送渠道（SMTP 或 Resend API Key）" });
  }

  const provider = smtpActive ? "SMTP" : "Resend";
  const fromDisplay = smtpActive
    ? (cfg.smtp_from || cfg.smtp_user)
    : (rcfg.resend_from_email || process.env.RESEND_FROM_EMAIL || "onboarding@resend.dev");

  try {
    await sendEmail({
      to,
      subject: `✅ ${siteName} 邮件测试（${provider}）`,
      html: adminNotifyHtml({
        subject: "邮件系统工作正常",
        body: `您好，这是来自 ${siteName} 管理后台的测试邮件。<br><br>
          <strong>发送渠道：</strong>${provider}<br>
          <strong>发件人：</strong><code>${fromDisplay}</code><br>
          <strong>收件人：</strong><code>${to}</code><br>
          <strong>发送时间：</strong>${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}<br><br>
          邮件配置正常，所有邮件功能（欢迎邮件、密码重置、域名到期提醒）均已就绪。`,
        siteName,
      }),
    });
    return res.status(200).json({ ok: true, to, provider });
  } catch (err: any) {
    console.error("[admin/test-email] error:", err.message);
    return res.status(500).json({ error: err.message || "发送失败" });
  }
}
