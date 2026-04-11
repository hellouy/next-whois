import type { NextApiRequest, NextApiResponse } from "next";
import { many, run } from "@/lib/db-query";
import { requireAdmin, getAdminEmail } from "@/lib/admin";
import { randomBytes } from "crypto";
import { sendEmail, passwordResetHtml, getSiteLabel } from "@/lib/email";

type Action = "disable" | "enable" | "grant_subscription" | "revoke_subscription" | "delete" | "send_reset_email";

const RESET_EXPIRES_MINUTES = 60;
const SITE_URL =
  process.env.NEXT_PUBLIC_BASE_URL ||
  process.env.NEXTAUTH_URL ||
  "https://x.rw";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { ids, action } = req.body as { ids: string[]; action: Action };

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: "ids 不能为空" });
  }
  if (!["disable", "enable", "grant_subscription", "revoke_subscription", "delete", "send_reset_email"].includes(action)) {
    return res.status(400).json({ error: "无效操作" });
  }
  if (ids.length > 200) {
    return res.status(400).json({ error: "单次最多处理 200 条" });
  }

  const placeholders = ids.map((_, i) => `$${i + 1}`).join(",");
  const adminEmail = await getAdminEmail();

  try {
    let affected = 0;
    switch (action) {
      case "disable":
        affected = await run(
          `UPDATE users SET disabled = true WHERE id IN (${placeholders}) AND email != $${ids.length + 1}`,
          [...ids, adminEmail],
        );
        break;
      case "enable":
        affected = await run(
          `UPDATE users SET disabled = false WHERE id IN (${placeholders})`,
          ids,
        );
        break;
      case "grant_subscription":
        affected = await run(
          `UPDATE users SET subscription_access = true WHERE id IN (${placeholders})`,
          ids,
        );
        break;
      case "revoke_subscription":
        affected = await run(
          `UPDATE users SET subscription_access = false WHERE id IN (${placeholders})`,
          ids,
        );
        break;
      case "delete":
        affected = await run(
          `DELETE FROM users WHERE id IN (${placeholders}) AND email != $${ids.length + 1}`,
          [...ids, adminEmail],
        );
        break;
      case "send_reset_email": {
        const rows = await many<{ id: string; email: string }>(
          `SELECT id, email FROM users WHERE id IN (${placeholders}) AND email != $${ids.length + 1}`,
          [...ids, adminEmail]
        );
        const siteName = await getSiteLabel().catch(() => "WHOIS");
        let sent = 0;
        const failedEmails: string[] = [];
        const settledResults = await Promise.allSettled(rows.map(async (row) => {
          await run(
            "UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false",
            [row.id]
          );
          const tokenId = randomBytes(8).toString("hex");
          const rawToken = randomBytes(32).toString("hex");
          const expiresAt = new Date(Date.now() + RESET_EXPIRES_MINUTES * 60 * 1000).toISOString();
          await run(
            "INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)",
            [tokenId, row.id, rawToken, expiresAt]
          );
          const resetUrl = `${SITE_URL}/reset-password?token=${rawToken}`;
          await sendEmail({
            to: row.email,
            subject: `重置你的 ${siteName} 密码（管理员触发）`,
            html: passwordResetHtml({ resetUrl, siteName }),
          });
          return row.email;
        }));
        settledResults.forEach((r, i) => {
          if (r.status === "fulfilled") {
            sent++;
          } else {
            failedEmails.push(rows[i].email);
            console.warn(`[users-bulk] send_reset_email failed for ${rows[i].email}:`, r.reason?.message ?? r.reason);
          }
        });
        affected = sent;
        if (failedEmails.length > 0) {
          return res.status(207).json({ ok: true, affected, failed: failedEmails, failedCount: failedEmails.length });
        }
        break;
      }
    }
    return res.status(200).json({ ok: true, affected });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: message });
  }
}
