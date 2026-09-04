import type { NextApiRequest, NextApiResponse } from "next";
import { paypalCaptureOrder, markOrderPaid } from "@/lib/payment";
import { isDbReady, one } from "@/lib/db-query";

export const config = { maxDuration: 15 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!(await isDbReady())) return res.redirect(`/payment/result?status=error&msg=db`);

  const orderId = typeof req.query.order === "string" ? req.query.order : null;

  if (!orderId) return res.redirect("/payment/result?status=cancel");

  try {
    const order = await one<{
      id: string; status: string; provider_order_id: string | null;
      amount: number; currency: string;
    }>(
      `SELECT id, status, provider_order_id, amount::float AS amount, currency FROM payment_orders WHERE id = $1`,
      [orderId]
    );

    if (!order) return res.redirect(`/payment/result?status=cancel`);
    if (order.status === "paid") return res.redirect(`/payment/result?order=${orderId}`);

    // Bind strictly to the order created by /api/payment/create. The client
    // may only select which order to capture — the PayPal order id must match
    // what we stored at creation time.
    const paypalOrderId = order.provider_order_id;
    if (!paypalOrderId) return res.redirect(`/payment/result?order=${orderId}&status=cancel`);

    const { status, captureId, amount, currency } = await paypalCaptureOrder(paypalOrderId);

    if (status === "COMPLETED") {
      // Verify captured amount/currency matches the DB order to prevent
      // amount-confusion (a paid capture for a different value must not
      // mark this order as paid).
      const captured = Number(amount);
      const orderCurrency = (order.currency === "CNY" ? "USD" : order.currency).toUpperCase();
      if (!Number.isFinite(captured) || captured + 0.001 < order.amount || captured > order.amount + 0.001 || (currency ?? "").toUpperCase() !== orderCurrency) {
        console.error(
          `[paypal capture] Order ${orderId} amount mismatch — order=${order.amount} ${orderCurrency}, captured=${amount} ${currency}; NOT marking paid`
        );
        return res.redirect(`/payment/result?order=${orderId}&status=error`);
      }

      await markOrderPaid({
        orderId,
        providerOrderId: captureId || paypalOrderId,
        webhookRaw: JSON.stringify({ paypal_order_id: paypalOrderId, capture_id: captureId, amount, currency }),
      });
      console.log(`[paypal capture] Order ${orderId} paid — capture=${captureId}`);
    } else {
      console.warn(`[paypal capture] Order ${orderId} — PayPal status=${status}`);
    }
  } catch (err: any) {
    console.error("[paypal capture]", err.message);
  }

  return res.redirect(`/payment/result?order=${orderId}`);
}
