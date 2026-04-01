import type { NextApiRequest, NextApiResponse } from "next";
import { one, isDbReady } from "@/lib/db-query";
import { sendEmail, stampVerifyTimeoutHtml, getSiteLabel } from "@/lib/email";
import { getEmailStrings } from "@/lib/email-strings";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { id, domain, appUrl } = req.body;
  if (!id || !domain) return res.status(400).json({ error: "Missing id or domain" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Database unavailable" });

  const stamp = await one<{ email: string; verify_token: string; verified: boolean }>(
    "SELECT s.email, s.verify_token, s.verified FROM stamps s WHERE s.id = $1 AND s.domain = $2",
    [id, String(domain).toLowerCase().trim()],
  );

  if (!stamp) return res.status(404).json({ error: "Stamp not found" });
  if (stamp.verified) return res.status(200).json({ skipped: true, reason: "already_verified" });

  const { email, verify_token } = stamp;
  const fileContent = `next-whois-verify=${verify_token}`;
  const appBase = (appUrl && String(appUrl).startsWith("http"))
    ? appUrl
    : (process.env.NEXT_PUBLIC_APP_URL || process.env.NEXT_PUBLIC_BASE_URL || "https://x.rw");
  const verifyUrl = `${appBase}/stamp?domain=${encodeURIComponent(domain)}`;

  const siteName = await getSiteLabel().catch(() => "X.RW");
  const userRow = await one<{ locale: string | null }>(
    "SELECT locale FROM users WHERE email = $1",
    [email],
  ).catch(() => null);
  const locale = userRow?.locale || "zh";
  const s = getEmailStrings(locale);

  await sendEmail({
    to: email,
    subject: s.subj_stamp_verify(domain),
    html: stampVerifyTimeoutHtml({ domain, fileContent, verifyUrl, siteName, locale }),
  });

  return res.status(200).json({ sent: true, to: email });
}
