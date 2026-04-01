import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { run, isDbReady } from "@/lib/db-query";
import { SUPPORTED_EMAIL_LOCALES, normalizeEmailLocale } from "@/lib/email-strings";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  const { locale } = req.body ?? {};
  if (!locale || typeof locale !== "string") return res.status(400).json({ error: "locale required" });

  const normalized = normalizeEmailLocale(locale);
  if (!SUPPORTED_EMAIL_LOCALES.has(normalized)) {
    return res.status(400).json({ error: "Unsupported locale" });
  }

  if (!(await isDbReady())) return res.status(500).json({ error: "Database unavailable" });

  try {
    await run(
      "UPDATE users SET locale = $1 WHERE email = $2",
      [normalized, session.user.email],
    );
    return res.json({ ok: true, locale: normalized });
  } catch (err: any) {
    console.error("[update-locale]", err.message);
    return res.status(500).json({ error: "Failed to update locale" });
  }
}
