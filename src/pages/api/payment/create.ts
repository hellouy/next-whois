import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { createOrder, type PaymentProvider } from "@/lib/payment";
import { isDbReady, one } from "@/lib/db-query";
import { many } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { getSetting } from "@/lib/server/site-settings-server";
import Stripe from "stripe";

export const config = { maxDuration: 15 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  // Rate-limit order creation: 5 per minute per IP
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`payment:create:${ip}`, 5, 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again later" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user) return res.status(401).json({ error: "Unauthorized" });

  const userEmail = (session.user as any).email as string;
  const dbUser = await one<{ id: string; subscription_access: boolean }>(
    `SELECT id, subscription_access FROM users WHERE email = $1`, [userEmail]
  );
  if (!dbUser) return res.status(404).json({ error: "User not found" });

  const { planId, provider } = req.body as { planId: string; provider: PaymentProvider };
  if (!planId || !provider) return res.status(400).json({ error: "Missing required parameters" });

  const validProviders = ["stripe", "xunhupay", "alipay", "paypal", "wechat"];
  if (!validProviders.includes(provider)) return res.status(400).json({ error: "Unsupported payment method" });

  const providerEnabled = await getSetting(`payment_${provider}_enabled`);
  if (!providerEnabled) return res.status(400).json({ error: "This payment method is not enabled" });

  try {
    const { order, plan } = await createOrder({
      userId: dbUser.id,
      userEmail,
      planId,
      provider,
    });

    const proto = req.headers["x-forwarded-proto"] ?? "https";
    const host = req.headers["x-forwarded-host"] ?? req.headers.host;
    const baseUrl = `${proto}://${host}`;

    if (provider === "stripe") {
      const stripeKey = (await getSetting("payment_stripe_sk")) || process.env.STRIPE_SECRET_KEY || "";
      if (!stripeKey) return res.status(500).json({ error: "Stripe is not configured (missing secret key)" });

      const stripe = new Stripe(stripeKey, { apiVersion: "2026-02-25.clover" });
      const currencyCode = (plan.currency || "CNY").toLowerCase();
      const isZeroDecimal = ["jpy", "krw", "vnd"].includes(currencyCode);
      const unitAmount = isZeroDecimal
        ? Math.round(plan.price)
        : Math.round(plan.price * 100);

      const checkoutSession = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [{
          price_data: {
            currency: currencyCode,
            product_data: { name: plan.name, description: plan.description ?? undefined },
            unit_amount: unitAmount,
          },
          quantity: 1,
        }],
        mode: "payment",
        success_url: `${baseUrl}/payment/result?order=${order.id}&status=success`,
        cancel_url: `${baseUrl}/payment/result?order=${order.id}&status=cancel`,
        metadata: { order_id: order.id },
        customer_email: userEmail,
      });

      await one(
        `UPDATE payment_orders SET provider_order_id=$2, metadata=$3 WHERE id=$1`,
        [order.id, checkoutSession.id, JSON.stringify({ checkout_session_id: checkoutSession.id })]
      );

      return res.json({ ok: true, provider: "stripe", url: checkoutSession.url, orderId: order.id });
    }

    if (provider === "xunhupay") {
      const appId = await getSetting("payment_xunhupay_appid");
      const appSecret = process.env.XUNHUPAY_APP_SECRET ?? "";
      if (!appId || !appSecret) return res.status(500).json({ error: "Xunhupay is not configured" });

      const { xunhupaySign } = await import("@/lib/payment");
      const params: Record<string, string> = {
        version:      "1.1",
        appid:        appId,
        trade_order_id: order.id,
        total_fee:    plan.price.toFixed(2),
        title:        plan.name,
        time:         Math.floor(Date.now() / 1000).toString(),
        notify_url:   `${baseUrl}/api/payment/webhook/xunhupay`,
        return_url:   `${baseUrl}/payment/result?order=${order.id}&status=success`,
        type:         "alipay",
        nonce_str:    Math.random().toString(36).slice(2),
      };
      params.sign = xunhupaySign(params, appSecret);
      params.sign_type = "MD5";

      return res.json({ ok: true, provider: "xunhupay", params, orderId: order.id,
        endpoint: "https://api.xunhupay.com/payment/do.html" });
    }

    if (provider === "alipay") {
      const appId = await getSetting("payment_alipay_appid");
      const privateKey = (await getSetting("payment_alipay_private_key")) || process.env.ALIPAY_PRIVATE_KEY || "";
      const alipayPublicKey = (await getSetting("payment_alipay_public_key")) || process.env.ALIPAY_PUBLIC_KEY || "";
      if (!appId || !privateKey) return res.status(500).json({ error: "Alipay is not configured" });

      const notifyUrl = await getSetting("payment_alipay_notify_url") ||
        `${baseUrl}/api/payment/webhook/alipay`;

      const bizContent = JSON.stringify({
        out_trade_no: order.id,
        total_amount: plan.price.toFixed(2),
        subject: plan.name,
        product_code: "FAST_INSTANT_TRADE_PAY",
      });

      const commonParams: Record<string, string> = {
        app_id:     appId,
        method:     "alipay.trade.page.pay",
        format:     "JSON",
        charset:    "utf-8",
        sign_type:  "RSA2",
        timestamp:  new Date().toISOString().replace("T", " ").slice(0, 19),
        version:    "1.0",
        notify_url: notifyUrl,
        return_url: `${baseUrl}/payment/result?order=${order.id}&status=success`,
        biz_content: bizContent,
      };

      const { createSign } = await import("crypto");
      const sortedStr = Object.keys(commonParams).sort()
        .map(k => `${k}=${commonParams[k]}`).join("&");

      const sign = createSign("RSA-SHA256");
      sign.update(sortedStr);
      const formattedKey = privateKey.includes("BEGIN") ? privateKey :
        `-----BEGIN PRIVATE KEY-----\n${privateKey.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----`;
      commonParams.sign = sign.sign(formattedKey, "base64");

      const alipayUrl = `https://openapi.alipay.com/gateway.do?${
        new URLSearchParams(commonParams).toString()}`;

      return res.json({ ok: true, provider: "alipay", url: alipayUrl, orderId: order.id });
    }

    if (provider === "wechat") {
      // WeChat Pay via Xunhupay gateway — reuses xunhupay credentials with type="wechat"
      const appId = await getSetting("payment_xunhupay_appid");
      const appSecret = (await getSetting("payment_xunhupay_secret")) || process.env.XUNHUPAY_APP_SECRET || "";
      if (!appId || !appSecret) return res.status(500).json({ error: "WeChat Pay is not configured (please set Xunhupay AppID/AppSecret in settings)" });

      const { xunhupaySign } = await import("@/lib/payment");
      const params: Record<string, string> = {
        version:        "1.1",
        appid:          appId,
        trade_order_id: order.id,
        total_fee:      plan.price.toFixed(2),
        title:          plan.name,
        time:           Math.floor(Date.now() / 1000).toString(),
        notify_url:     `${baseUrl}/api/payment/webhook/xunhupay`,
        return_url:     `${baseUrl}/payment/result?order=${order.id}&status=success`,
        type:           "wechat",
        nonce_str:      Math.random().toString(36).slice(2),
      };
      params.sign = xunhupaySign(params, appSecret);
      params.sign_type = "MD5";

      return res.json({ ok: true, provider: "wechat", params, orderId: order.id,
        endpoint: "https://api.xunhupay.com/payment/do.html" });
    }

    if (provider === "paypal") {
      const { paypalCreateOrder } = await import("@/lib/payment");
      const paypalOrder = await paypalCreateOrder({
        orderId: order.id,
        amount: plan.price,
        currency: plan.currency === "CNY" ? "USD" : plan.currency,
        description: plan.name,
        returnUrl: `${baseUrl}/api/payment/capture/paypal?order=${order.id}`,
        cancelUrl: `${baseUrl}/payment/result?order=${order.id}&status=cancel`,
      });

      await one(
        `UPDATE payment_orders SET provider_order_id=$2, metadata=$3 WHERE id=$1`,
        [order.id, paypalOrder.id, JSON.stringify({ paypal_order_id: paypalOrder.id })]
      );

      return res.json({ ok: true, provider: "paypal", url: paypalOrder.approveUrl, orderId: order.id });
    }

    return res.status(400).json({ error: "Unsupported payment method" });
  } catch (err: any) {
    console.error("[payment/create]", err);
    return res.status(500).json({ error: err.message || "Failed to create order" });
  }
}
