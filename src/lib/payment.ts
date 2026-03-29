import { randomBytes, createHash, createHmac } from "crypto";
import { run, one, many } from "@/lib/db-query";
import { sendEmail, paymentConfirmHtml, getSiteLabel } from "@/lib/email";

export type PaymentProvider = "stripe" | "xunhupay" | "alipay" | "paypal";
export type OrderStatus = "pending" | "paid" | "failed" | "expired" | "refunded";

export interface PaymentPlan {
  id: string;
  name: string;
  description: string | null;
  price: number;
  currency: string;
  duration_days: number | null;
  is_recurring: boolean;
  grants_subscription: boolean;
  balance_grant_cents: number;
  is_active: boolean;
  sort_order: number;
}

export interface PaymentOrder {
  id: string;
  user_id: string | null;
  user_email: string;
  plan_id: string | null;
  plan_name: string;
  amount: number;
  currency: string;
  provider: PaymentProvider;
  provider_order_id: string | null;
  status: OrderStatus;
  paid_at: string | null;
  created_at: string;
}

export function genOrderId(): string {
  return randomBytes(12).toString("hex").toUpperCase();
}

export async function getActivePlans(): Promise<PaymentPlan[]> {
  const rows = await many<PaymentPlan>(
    `SELECT id, name, description, price::float AS price, currency,
            duration_days, is_recurring, grants_subscription,
            COALESCE(balance_grant_cents, 0) AS balance_grant_cents,
            is_active, sort_order
     FROM payment_plans WHERE is_active = true ORDER BY sort_order ASC, price ASC`
  );
  return rows;
}

export async function createOrder(params: {
  userId: string | null;
  userEmail: string;
  planId: string;
  provider: PaymentProvider;
}): Promise<{ order: PaymentOrder; plan: PaymentPlan }> {
  const plan = await one<PaymentPlan>(
    `SELECT id, name, description, price::float AS price, currency,
            duration_days, is_recurring, grants_subscription,
            COALESCE(balance_grant_cents, 0) AS balance_grant_cents,
            is_active, sort_order
     FROM payment_plans WHERE id = $1 AND is_active = true`,
    [params.planId]
  );
  if (!plan) throw new Error("套餐不存在或已下线");

  const id = genOrderId();
  const expiredAt = new Date(Date.now() + 30 * 60 * 1000); // 30 min to pay

  await run(
    `INSERT INTO payment_orders
       (id, user_id, user_email, plan_id, plan_name, amount, currency, provider, status, expired_at, balance_grant_cents)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10)`,
    [id, params.userId, params.userEmail, plan.id, plan.name,
     plan.price, plan.currency, params.provider, expiredAt.toISOString(),
     plan.balance_grant_cents ?? 0]
  );

  const order = await one<PaymentOrder>(
    `SELECT id, user_id, user_email, plan_id, plan_name, amount::float AS amount,
            currency, provider, provider_order_id, status, paid_at, created_at
     FROM payment_orders WHERE id = $1`,
    [id]
  );
  return { order: order!, plan };
}

export async function markOrderPaid(params: {
  orderId: string;
  providerOrderId?: string;
  webhookRaw?: string;
}): Promise<{ alreadyPaid: boolean; userEmail: string; grantsSubscription: boolean }> {
  const order = await one<{
    id: string; status: string; user_id: string | null;
    user_email: string; plan_id: string | null;
  }>(
    `SELECT id, status, user_id, user_email, plan_id FROM payment_orders WHERE id = $1`,
    [params.orderId]
  );
  if (!order) throw new Error("订单不存在");
  if (order.status === "paid") return { alreadyPaid: true, userEmail: order.user_email, grantsSubscription: false };

  await run(
    `UPDATE payment_orders
     SET status='paid', paid_at=NOW(),
         provider_order_id=COALESCE($2, provider_order_id),
         webhook_raw=COALESCE($3, webhook_raw)
     WHERE id=$1`,
    [params.orderId, params.providerOrderId ?? null, params.webhookRaw ?? null]
  );

  let grantsSubscription = false;
  let balanceGrantCents = 0;
  if (order.plan_id) {
    const plan = await one<{ grants_subscription: boolean; balance_grant_cents: number }>(
      `SELECT grants_subscription, COALESCE(balance_grant_cents, 0) AS balance_grant_cents FROM payment_plans WHERE id = $1`,
      [order.plan_id]
    );
    grantsSubscription = plan?.grants_subscription ?? false;
    balanceGrantCents = plan?.balance_grant_cents ?? 0;
  }
  // Also check the order-level balance_grant_cents (populated at order creation)
  if (!balanceGrantCents) {
    const orderRow = await one<{ balance_grant_cents: number }>(
      `SELECT COALESCE(balance_grant_cents, 0) AS balance_grant_cents FROM payment_orders WHERE id = $1`,
      [params.orderId]
    );
    balanceGrantCents = orderRow?.balance_grant_cents ?? 0;
  }

  if (grantsSubscription) {
    const planRow = order.plan_id ? await one<{ duration_days: number | null }>(
      `SELECT duration_days FROM payment_plans WHERE id = $1`, [order.plan_id]
    ) : null;
    const durationDays = planRow?.duration_days ?? null;

    if (order.user_id) {
      if (durationDays) {
        await run(
          `UPDATE users SET subscription_access = TRUE, updated_at = NOW(),
           subscription_expires_at = GREATEST(COALESCE(subscription_expires_at, NOW()), NOW()) + ($2 || ' days')::INTERVAL
           WHERE id = $1`,
          [order.user_id, durationDays]
        );
      } else {
        await run(
          `UPDATE users SET subscription_access = TRUE, updated_at = NOW(), subscription_expires_at = NULL WHERE id = $1`,
          [order.user_id]
        );
      }
    } else if (order.user_email) {
      if (durationDays) {
        await run(
          `UPDATE users SET subscription_access = TRUE, updated_at = NOW(),
           subscription_expires_at = GREATEST(COALESCE(subscription_expires_at, NOW()), NOW()) + ($2 || ' days')::INTERVAL
           WHERE email = $1`,
          [order.user_email, durationDays]
        );
      } else {
        await run(
          `UPDATE users SET subscription_access = TRUE, updated_at = NOW(), subscription_expires_at = NULL WHERE email = $1`,
          [order.user_email]
        );
      }
    }
  }

  // Credit balance if applicable
  if (balanceGrantCents > 0) {
    const uid = order.user_id;
    const email = order.user_email;
    if (uid) {
      await run(`UPDATE users SET balance_cents = balance_cents + $2 WHERE id = $1`, [uid, balanceGrantCents]);
      await run(
        `INSERT INTO balance_transactions (user_id, amount_cents, type, description) VALUES ($1, $2, 'recharge', $3)`,
        [uid, balanceGrantCents, `支付充值（订单 ${params.orderId}）`]
      );
    } else if (email) {
      const u = await one<{ id: string }>(`SELECT id FROM users WHERE email = $1`, [email]);
      if (u) {
        await run(`UPDATE users SET balance_cents = balance_cents + $2 WHERE id = $1`, [u.id, balanceGrantCents]);
        await run(
          `INSERT INTO balance_transactions (user_id, amount_cents, type, description) VALUES ($1, $2, 'recharge', $3)`,
          [u.id, balanceGrantCents, `支付充值（订单 ${params.orderId}）`]
        );
      }
    }
  }

  const paidOrder = await one<{ plan_name: string; amount: number; currency: string }>(
    `SELECT plan_name, amount::float AS amount, currency FROM payment_orders WHERE id=$1`,
    [params.orderId]
  );
  const userRow = await one<{ name: string | null }>(
    `SELECT name FROM users WHERE id=$1 OR email=$2 LIMIT 1`,
    [order.user_id ?? "", order.user_email]
  );
  // Record payment as a sponsor entry with the correct currency from the order
  await run(
    `INSERT INTO sponsors (id, name, avatar_url, amount, currency, message, sponsor_date, is_anonymous, is_visible, platform)
     VALUES ($1, $2, NULL, $3, $4, $5, CURRENT_DATE, false, false, $6)
     ON CONFLICT DO NOTHING`,
    [
      randomBytes(8).toString("hex"),
      order.user_email,
      paidOrder?.amount ?? 0,
      paidOrder?.currency ?? "CNY",
      "通过支付系统赞助",
      order.plan_id ?? "payment",
    ]
  ).catch(e => console.warn("[markOrderPaid] sponsor insert error:", e));

  const siteName = await getSiteLabel();
  sendEmail({
    to: order.user_email,
    subject: `支付成功 — 您的会员订阅已开通 | ${siteName}`,
    html: paymentConfirmHtml({
      name: userRow?.name ?? null,
      email: order.user_email,
      planName: paidOrder?.plan_name ?? "订阅套餐",
      amount: paidOrder?.amount ?? 0,
      currency: paidOrder?.currency ?? "CNY",
      orderId: params.orderId,
      siteName,
    }),
  }).catch(e => console.error("[markOrderPaid] email error:", e));

  return { alreadyPaid: false, userEmail: order.user_email, grantsSubscription };
}

export async function getOrderById(orderId: string): Promise<PaymentOrder | null> {
  return one<PaymentOrder>(
    `SELECT id, user_id, user_email, plan_id, plan_name, amount::float AS amount,
            currency, provider, provider_order_id, status, paid_at, created_at
     FROM payment_orders WHERE id = $1`,
    [orderId]
  );
}

export function xunhupaySign(params: Record<string, string>, appSecret: string): string {
  const sorted = Object.keys(params)
    .filter(k => k !== "sign" && params[k] !== "")
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join("&");
  return createHash("md5").update(sorted + appSecret).digest("hex");
}

export function verifyXunhupayWebhook(body: Record<string, string>, appSecret: string): boolean {
  const { sign, ...rest } = body;
  if (!sign) return false;
  const expected = xunhupaySign(rest, appSecret);
  return sign.toLowerCase() === expected.toLowerCase();
}

export function verifyStripeWebhookSignature(
  payload: string,
  sigHeader: string,
  secret: string
): boolean {
  try {
    const parts = sigHeader.split(",").reduce<Record<string, string>>((acc, p) => {
      const [k, v] = p.split("=");
      acc[k.trim()] = v?.trim() ?? "";
      return acc;
    }, {});
    const timestamp = parts["t"];
    const signatures = Object.entries(parts)
      .filter(([k]) => k === "v1")
      .map(([, v]) => v);
    if (!timestamp || signatures.length === 0) return false;
    const signedPayload = `${timestamp}.${payload}`;
    const expected = createHmac("sha256", secret).update(signedPayload).digest("hex");
    return signatures.some(s => s === expected);
  } catch {
    return false;
  }
}

// ── PayPal REST API helpers ────────────────────────────────────────────────

async function getPaypalBase(): Promise<string> {
  try {
    const row = await one<{ value: string }>(
      `SELECT value FROM site_settings WHERE key = 'payment_paypal_env'`
    );
    const env = row?.value || process.env.PAYPAL_ENV || "live";
    return env === "sandbox" ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com";
  } catch {
    return process.env.PAYPAL_ENV === "sandbox"
      ? "https://api-m.sandbox.paypal.com"
      : "https://api-m.paypal.com";
  }
}

export async function paypalGetToken(): Promise<string> {
  // DB-first with env var fallback
  let clientId = "";
  let secret = "";
  try {
    const rows = await many<{ key: string; value: string }>(
      `SELECT key, value FROM site_settings WHERE key IN ('payment_paypal_client_id','payment_paypal_client_secret')`
    );
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    clientId = map.payment_paypal_client_id || process.env.PAYPAL_CLIENT_ID || "";
    secret = map.payment_paypal_client_secret || process.env.PAYPAL_CLIENT_SECRET || "";
  } catch {
    clientId = process.env.PAYPAL_CLIENT_ID || "";
    secret = process.env.PAYPAL_CLIENT_SECRET || "";
  }
  if (!clientId || !secret) throw new Error("PayPal 未配置 Client ID / Secret");
  const PAYPAL_BASE = await getPaypalBase();
  const basic = Buffer.from(`${clientId}:${secret}`).toString("base64");
  const res = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  const data = await res.json() as any;
  if (!data.access_token) throw new Error("PayPal access token 获取失败");
  return data.access_token;
}

export async function paypalCreateOrder(params: {
  orderId: string; amount: number; currency: string;
  description: string; returnUrl: string; cancelUrl: string;
}): Promise<{ id: string; approveUrl: string }> {
  const token = await paypalGetToken();
  const PAYPAL_BASE = await getPaypalBase();
  const res = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [{
        reference_id: params.orderId,
        description: params.description,
        amount: { currency_code: params.currency.toUpperCase(), value: params.amount.toFixed(2) },
      }],
      payment_source: {
        paypal: {
          experience_context: {
            return_url: params.returnUrl,
            cancel_url: params.cancelUrl,
            user_action: "PAY_NOW",
          },
        },
      },
    }),
  });
  const data = await res.json() as any;
  if (data.status !== "CREATED") throw new Error(`PayPal 创建订单失败: ${data.message ?? JSON.stringify(data)}`);
  const approveLink = data.links?.find((l: any) => l.rel === "payer-action" || l.rel === "approve");
  if (!approveLink) throw new Error("PayPal 未返回支付链接");
  return { id: data.id, approveUrl: approveLink.href };
}

export async function paypalCaptureOrder(paypalOrderId: string): Promise<{ status: string; captureId: string }> {
  const token = await paypalGetToken();
  const PAYPAL_BASE = await getPaypalBase();
  const res = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${paypalOrderId}/capture`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  const data = await res.json() as any;
  const captureStatus = data.status;
  const captureId = data.purchase_units?.[0]?.payments?.captures?.[0]?.id ?? data.id;
  return { status: captureStatus, captureId };
}

export function verifyAlipaySign(
  params: Record<string, string>,
  publicKey: string
): boolean {
  const { sign, sign_type, ...rest } = params;
  if (!sign) return false;
  const sorted = Object.keys(rest)
    .filter(k => rest[k] !== "" && rest[k] !== undefined)
    .sort()
    .map(k => `${k}=${rest[k]}`)
    .join("&");
  try {
    const { createVerify } = require("crypto");
    const verify = createVerify("RSA-SHA256");
    verify.update(sorted);
    const pubKey = publicKey.includes("BEGIN") ? publicKey :
      `-----BEGIN PUBLIC KEY-----\n${publicKey.match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----`;
    return verify.verify(pubKey, sign, "base64");
  } catch {
    return false;
  }
}
