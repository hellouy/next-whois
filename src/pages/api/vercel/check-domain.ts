import type { NextApiRequest, NextApiResponse } from "next";
import { one, run, isDbReady } from "@/lib/db-query";

export const config = { maxDuration: 15 };

const VERCEL_API = "https://api.vercel.com";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { domain, stampId } = req.body;
  if (!domain || !stampId)
    return res.status(400).json({ error: "Missing domain or stampId" });

  if (!process.env.VERCEL_API_TOKEN || !process.env.VERCEL_PROJECT_ID)
    return res.status(503).json({ error: "Vercel integration not configured" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const stamp = await one<{ id: string; verified: boolean }>(
    "SELECT id, verified FROM stamps WHERE id = $1 AND domain = $2",
    [stampId, String(domain).toLowerCase().trim()],
  );
  if (!stamp) return res.status(404).json({ error: "Stamp not found" });
  if (stamp.verified) return res.status(200).json({ verified: true, already: true });

  const verifyRes = await fetch(
    `${VERCEL_API}/v9/projects/${process.env.VERCEL_PROJECT_ID}/domains/${domain}/verify`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.VERCEL_API_TOKEN}`,
        "Content-Type": "application/json",
      },
    },
  );
  const verifyData = await verifyRes.json();

  if (!verifyRes.ok) {
    return res.status(200).json({
      verified: false,
      apiError: verifyData.error?.message ?? "Vercel verification check failed",
    });
  }

  if (verifyData.verified) {
    await run(
      "UPDATE stamps SET verified = true, verified_at = $1 WHERE id = $2",
      [new Date().toISOString(), stampId],
    );
    return res.status(200).json({ verified: true });
  }

  return res.status(200).json({ verified: false, pending: true });
}
