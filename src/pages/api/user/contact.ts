import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { sendEmail, getSiteLabel } from "@/lib/email";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { checkRateLimit } from "@/lib/rate-limit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // Rate-limit: 3 messages per hour per IP to prevent spam
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`contact:${ip}`, 3, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many messages, please try again later" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  const { message, category } = req.body;
  if (!message || typeof message !== "string" || !message.trim()) {
    return res.status(400).json({ error: "Message content cannot be empty" });
  }

  const VALID_CATEGORIES = ["支付问题", "会员问题", "功能问题", "其他问题"];
  const safeCategory = VALID_CATEGORIES.includes(category) ? category : "其他问题";

  const userEmail = session.user.email;
  const userName  = (session.user as any)?.name || userEmail;
  const siteName  = await getSiteLabel().catch(() => "X.RW");
  const isMember  = !!(session.user as any)?.subscriptionAccess;

  const CATEGORY_COLORS: Record<string, string> = {
    "支付问题": "#0ea5e9",
    "会员问题": "#8b5cf6",
    "功能问题": "#f59e0b",
    "其他问题": "#6b7280",
  };
  const catColor = CATEGORY_COLORS[safeCategory] ?? "#6b7280";

  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#1a1a1a">
      <h2 style="font-size:18px;font-weight:700;margin-bottom:4px">📩 新客服消息 · ${siteName}</h2>
      <p style="font-size:13px;color:#6b7280;margin-bottom:20px">来自用户中心联系客服表单</p>
      <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
        <tr>
          <td style="padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;width:100px;font-size:12px;font-weight:600;color:#374151">用户</td>
          <td style="padding:8px 12px;border:1px solid #e5e7eb;font-size:13px">${userName}</td>
        </tr>
        <tr>
          <td style="padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;font-size:12px;font-weight:600;color:#374151">邮箱</td>
          <td style="padding:8px 12px;border:1px solid #e5e7eb;font-size:13px"><a href="mailto:${userEmail}">${userEmail}</a></td>
        </tr>
        <tr>
          <td style="padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;font-size:12px;font-weight:600;color:#374151">身份</td>
          <td style="padding:8px 12px;border:1px solid #e5e7eb;font-size:13px">${isMember ? "会员 ✓" : "普通用户"}</td>
        </tr>
        <tr>
          <td style="padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;font-size:12px;font-weight:600;color:#374151">问题类型</td>
          <td style="padding:8px 12px;border:1px solid #e5e7eb;font-size:13px">
            <span style="display:inline-block;padding:2px 8px;border-radius:9999px;background:${catColor}20;color:${catColor};font-size:11px;font-weight:600">${safeCategory}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 12px;background:#f9fafb;border:1px solid #e5e7eb;font-size:12px;font-weight:600;color:#374151;vertical-align:top">内容</td>
          <td style="padding:8px 12px;border:1px solid #e5e7eb;font-size:13px;line-height:1.6;white-space:pre-wrap">${message.trim().slice(0, 500)}</td>
        </tr>
      </table>
      <p style="font-size:11px;color:#9ca3af">请直接回复此邮件即可联系用户 · ${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}</p>
    </div>
  `;

  try {
    await sendEmail({
      to: ADMIN_EMAIL,
      subject: `[客服·${safeCategory}] ${userName} · ${siteName}`,
      html,
    });
    return res.status(200).json({ ok: true });
  } catch (err: any) {
    console.error("[user/contact] send error:", err.message);
    return res.status(500).json({ error: "Failed to send message, please try again" });
  }
}
