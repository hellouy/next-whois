import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { getOrderById } from "@/lib/payment";
import { isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user) return res.status(401).json({ error: "Unauthorized" });

  const orderId = typeof req.query.order === "string" ? req.query.order : "";
  if (!orderId) return res.status(400).json({ error: "Missing order ID" });

  const order = await getOrderById(orderId);
  if (!order) return res.status(404).json({ error: "Order not found" });

  const userEmail = (session.user as any).email as string;
  if (order.user_email !== userEmail) return res.status(403).json({ error: "You do not have permission to view this order" });

  return res.json({ order: {
    id: order.id,
    status: order.status,
    amount: order.amount,
    currency: order.currency,
    plan_name: order.plan_name,
    provider: order.provider,
    paid_at: order.paid_at,
    created_at: order.created_at,
  }});
}
