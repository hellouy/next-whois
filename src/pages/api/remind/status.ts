import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const { domain } = req.query;
  if (!domain || typeof domain !== "string") {
    return res.status(400).json({ error: "Missing domain" });
  }

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) {
    return res.status(200).json({ subscribed: false });
  }

  if (!(await isDbReady())) {
    return res.status(200).json({ subscribed: false });
  }

  const email = session.user.email;
  const cleanDomain = String(domain)
    .toLowerCase()
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "")
    .replace(/\/.*$/, "");

  const existing = await one<{ id: string }>(
    "SELECT id FROM reminders WHERE domain = $1 AND email = $2 AND active = true",
    [cleanDomain, email],
  ).catch(() => null);

  return res.status(200).json({ subscribed: !!existing });
}
