import type { NextApiRequest, NextApiResponse } from "next";
import { markOrderPaid, verifyStripeWebhookSignature } from "@/lib/payment";
import { isDbReady } from "@/lib/db-query";
import { getSetting } from "@/lib/server/site-settings-server";

export const config = { api: { bodyParser: false } };

async function getRawBody(req: NextApiRequest): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).end();

  const rawBody = await getRawBody(req);
  const sig = req.headers["stripe-signature"] as string;
  const webhookSecret = (await getSetting("payment_stripe_webhook_secret")) || process.env.STRIPE_WEBHOOK_SECRET || "";

  if (!webhookSecret) {
    console.warn("[stripe webhook] payment_stripe_webhook_secret not configured");
    return res.status(500).json({ error: "Webhook secret not configured" });
  }

  if (!verifyStripeWebhookSignature(rawBody, sig ?? "", webhookSecret)) {
    console.warn("[stripe webhook] Invalid signature");
    return res.status(400).json({ error: "Invalid signature" });
  }

  let event: any;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data?.object;
    const orderId = session?.metadata?.order_id;
    const sessionId = session?.id;
    if (!orderId) return res.status(200).json({ ok: true });

    try {
      const result = await markOrderPaid({
        orderId,
        providerOrderId: sessionId,
        webhookRaw: rawBody.slice(0, 2000),
      });
      console.log(`[stripe webhook] Order ${orderId} paid — email=${result.userEmail} sub=${result.grantsSubscription}`);
    } catch (err: any) {
      console.error("[stripe webhook] markOrderPaid error:", err.message);
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(200).json({ received: true });
}
