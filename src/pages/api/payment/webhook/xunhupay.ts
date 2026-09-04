import type { NextApiRequest, NextApiResponse } from "next";
import { markOrderPaid, verifyXunhupayWebhook } from "@/lib/payment";
import { isDbReady } from "@/lib/db-query";
import { getSetting } from "@/lib/server/site-settings-server";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/payment/webhook/xunhupay");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).end();

  const body = req.body as Record<string, string>;
  const appSecret = (await getSetting("payment_xunhupay_secret")) || process.env.XUNHUPAY_APP_SECRET || "";

  if (!appSecret) {
    logger.warn("[xunhupay webhook] payment_xunhupay_secret not configured");
    return res.status(500).end();
  }

  if (!verifyXunhupayWebhook(body, appSecret)) {
    logger.warn("[xunhupay webhook] Invalid signature, body:", JSON.stringify(body).slice(0, 200));
    return res.status(400).json({ errcode: 1, errmsg: "invalid sign" });
  }

  const { trade_status, out_trade_no, transaction_id } = body;

  if (trade_status !== "TRADE_SUCCESS") {
    return res.json({ errcode: 0, errmsg: "ok" });
  }

  if (!out_trade_no) return res.status(400).json({ errcode: 1, errmsg: "missing order id" });

  try {
    const result = await markOrderPaid({
      orderId: out_trade_no,
      providerOrderId: transaction_id,
      webhookRaw: JSON.stringify(body).slice(0, 2000),
    });
    logger.info(`[xunhupay webhook] Order ${out_trade_no} paid — email=${result.userEmail} sub=${result.grantsSubscription}`);
  } catch (err: any) {
    logger.error("[xunhupay webhook] markOrderPaid error:", err.message);
    return res.status(500).json({ errcode: 1, errmsg: err.message });
  }

  return res.json({ errcode: 0, errmsg: "ok" });
}
