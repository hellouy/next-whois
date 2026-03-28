import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";

import { isAdmin } from "@/lib/admin";
import { many, isDbReady } from "@/lib/db-query";
import { sendEmail, adminBroadcastHtml, getSiteLabel } from "@/lib/email";

export const config = { maxDuration: 300 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email || !isAdmin(session.user.email))
    return res.status(403).json({ error: "无权限" });

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  if (req.method === "GET") {
    const { recipients } = req.query;
    let rows: { count: string }[] = [];
    if (recipients === "all") {
      rows = await many<{ count: string }>("SELECT COUNT(*)::text AS count FROM users WHERE disabled IS NOT TRUE AND email IS NOT NULL");
    } else if (recipients === "subscribed") {
      rows = await many<{ count: string }>("SELECT COUNT(*)::text AS count FROM users WHERE disabled IS NOT TRUE AND subscription_access IS TRUE AND email IS NOT NULL");
    }
    return res.status(200).json({ count: parseInt(rows[0]?.count ?? "0") });
  }

  if (req.method !== "POST") return res.status(405).end();

  const { subject, bodyHtml, recipients } = req.body as {
    subject: string;
    bodyHtml: string;
    recipients: "all" | "subscribed" | string[];
  };

  if (!subject?.trim() || !bodyHtml?.trim())
    return res.status(400).json({ error: "主题和内容不能为空" });

  let emails: string[] = [];

  if (recipients === "all") {
    const rows = await many<{ email: string }>(
      "SELECT email FROM users WHERE disabled IS NOT TRUE AND email IS NOT NULL ORDER BY created_at ASC"
    );
    emails = rows.map(r => r.email);
  } else if (recipients === "subscribed") {
    const rows = await many<{ email: string }>(
      "SELECT email FROM users WHERE disabled IS NOT TRUE AND subscription_access IS TRUE AND email IS NOT NULL ORDER BY created_at ASC"
    );
    emails = rows.map(r => r.email);
  } else if (Array.isArray(recipients)) {
    emails = recipients.filter(e => typeof e === "string" && e.includes("@"));
  } else {
    return res.status(400).json({ error: "recipients 参数无效" });
  }

  if (emails.length === 0) return res.status(400).json({ error: "没有符合条件的收件人" });

  const siteName = await getSiteLabel();

  let sent = 0;
  let failed = 0;

  for (const email of emails) {
    try {
      await sendEmail({
        to: email,
        subject: `${subject} | ${siteName}`,
        html: adminBroadcastHtml({ subject, bodyHtml, siteName }),
      });
      sent++;
    } catch {
      failed++;
    }
    if (emails.length > 1) {
      await new Promise(r => setTimeout(r, 120));
    }
  }

  return res.status(200).json({ ok: true, sent, failed, total: emails.length });
}
