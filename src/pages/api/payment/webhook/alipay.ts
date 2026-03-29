import type { NextApiRequest, NextApiResponse } from "next";
import { markOrderPaid, verifyAlipaySign } from "@/lib/payment";
import { isDbReady, one } from "@/lib/db-query";

async function getSetting(key: string): Promise<string> {
  const row = await one<{ value: string }>(`SELECT value FROM site_settings WHERE key=$1`, [key]);
  return row?.value ?? "";
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).end();

  const body = req.body as Record<string, string>;
  const alipayPublicKey = (await getSetting("payment_alipay_public_key")) || process.env.ALIPAY_PUBLIC_KEY || "";

  if (!alipayPublicKey) {
    console.warn("[alipay webhook] payment_alipay_public_key not configured");
    return res.status(200).send("fail");
  }

  const isValid = verifyAlipaySign(body, alipayPublicKey);
  if (!isValid) {
    console.warn("[alipay webhook] Signature verification failed");
    return res.status(200).send("fail");
  }

  const { trade_status, out_trade_no, trade_no } = body;

  if (trade_status !== "TRADE_SUCCESS" && trade_status !== "TRADE_FINISHED") {
    return res.status(200).send("success");
  }

  if (!out_trade_no) return res.status(200).send("fail");

  try {
    const result = await markOrderPaid({
      orderId: out_trade_no,
      providerOrderId: trade_no,
      webhookRaw: JSON.stringify(body).slice(0, 2000),
    });
    console.log(`[alipay webhook] Order ${out_trade_no} paid — email=${result.userEmail} sub=${result.grantsSubscription}`);
  } catch (err: any) {
    console.error("[alipay webhook] markOrderPaid error:", err.message);
    return res.status(200).send("fail");
  }

  return res.status(200).send("success");
}
