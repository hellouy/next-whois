import type { NextApiRequest, NextApiResponse } from "next";
import { getActivePlans } from "@/lib/payment";
import { isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  try {
    const plans = await getActivePlans();
    res.setHeader("Cache-Control", "public, max-age=120, stale-while-revalidate=300");
    return res.json({ plans });
  } catch (err: any) {
    console.error("[payment/plans] error:", err.message);
    return res.status(500).json({ error: "Failed to retrieve plans, please try again" });
  }
}
