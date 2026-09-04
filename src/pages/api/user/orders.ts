import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, isDbReady } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/orders");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  try {
    const orders = await many(
      `SELECT id, plan_name, amount::float AS amount, currency,
              provider, status, paid_at, created_at
       FROM payment_orders
       WHERE user_email = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [session.user.email]
    );
    return res.json({ orders });
  } catch (err: any) {
    logger.error("[user/orders]", err.message);
    return res.status(500).json({ error: "Failed to retrieve orders" });
  }
}
