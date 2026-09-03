import type { NextApiRequest, NextApiResponse } from "next";
import { markOrderPaid, paypalGetToken } from "@/lib/payment";
import { isDbReady, one } from "@/lib/db-query";
import { getSetting } from "@/lib/server/site-settings-server";

export const config = { api: { bodyParser: true } };

async function verifyPaypalWebhook(
  webhookId: string,
  req: NextApiRequest,
  body: any
): Promise<boolean> {
  if (!webhookId) return false;
  try {
    const token = await paypalGetToken();
    const verifyRes = await fetch("https://api-m.paypal.com/v1/notifications/verify-webhook-signature", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        transmission_id:   req.headers["paypal-transmission-id"],
        transmission_time: req.headers["paypal-transmission-time"],
        cert_url:          req.headers["paypal-cert-url"],
        auth_algo:         req.headers["paypal-auth-algo"],
        transmission_sig:  req.headers["paypal-transmission-sig"],
        webhook_id:        webhookId,
        webhook_event:     body,
      }),
    });
    const data = await verifyRes.json() as any;
    return data.verification_status === "SUCCESS";
  } catch {
    return false;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).end();

  const webhookId = (await getSetting("payment_paypal_webhook_id")) || process.env.PAYPAL_WEBHOOK_ID || "";
  const body = req.body;

  // SECURITY: without a configured webhook id we cannot verify the signature,
  // so payment events must be rejected instead of trusted.
  if (!webhookId) {
    console.error("[paypal webhook] Rejected: PAYPAL_WEBHOOK_ID not configured");
    return res.status(503).json({ error: "Webhook not configured" });
  }

  const valid = await verifyPaypalWebhook(webhookId, req, body);
  if (!valid) {
    console.warn("[paypal webhook] Invalid signature");
    return res.status(400).json({ error: "Invalid signature" });
  }

  const eventType = body?.event_type as string | undefined;
  console.log(`[paypal webhook] event_type=${eventType}`);

  if (eventType === "PAYMENT.CAPTURE.COMPLETED") {
    const capture = body?.resource;
    const captureId = capture?.id;
    const paypalOrderId = capture?.supplementary_data?.related_ids?.order_id
      ?? capture?.links?.find((l: any) => l.rel === "up")?.href?.split("/").pop();

    let orderId: string | null = null;

    // SECURITY: only match by the exact provider order id carried in the
    // verified event. No fuzzy fallback — a forged callback must never be
    // able to mark an unrelated pending order as paid.
    if (paypalOrderId) {
      const row = await one<{ id: string }>(
        `SELECT id FROM payment_orders WHERE provider_order_id = $1 AND status != 'paid'`,
        [paypalOrderId]
      );
      orderId = row?.id ?? null;
    }

    if (orderId) {
      try {
        const result = await markOrderPaid({
          orderId,
          providerOrderId: captureId ?? paypalOrderId,
          webhookRaw: JSON.stringify(body).slice(0, 2000),
        });
        console.log(`[paypal webhook] Order ${orderId} marked paid — sub=${result.grantsSubscription}`);
      } catch (err: any) {
        console.error("[paypal webhook] markOrderPaid error:", err.message);
      }
    }
  }

  return res.status(200).json({ received: true });
}
