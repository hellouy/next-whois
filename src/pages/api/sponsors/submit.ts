import type { NextApiRequest, NextApiResponse } from "next";
import { run, isDbReady } from "@/lib/db-query";
import { randomBytes } from "crypto";
import { checkRateLimit } from "@/lib/rate-limit";

export const config = { maxDuration: 10 };

function genId() {
  return randomBytes(8).toString("hex");
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Rate-limit manual sponsor submissions — 3 per hour per IP
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`sponsor:submit:${ip}`, 3, 60 * 60 * 1000);
  if (!rl.ok) {
    return res.status(429).json({ error: "Too many submissions, please try again later" });
  }

  if (!(await isDbReady())) {
    return res.status(503).json({ error: "Database unavailable" });
  }

  const { name, message, amount, currency, platform, is_anonymous } = req.body;

  if (!name?.trim() && !is_anonymous) {
    return res.status(400).json({ error: "Please enter your name or choose to remain anonymous" });
  }

  // Validate currency (fiat + crypto)
  const ALLOWED_CURRENCIES = ["CNY", "USD", "EUR", "GBP", "JPY", "HKD", "USDT", "BTC", "ETH"];
  const cleanCurrency = ALLOWED_CURRENCIES.includes(String(currency || "").toUpperCase())
    ? String(currency).toUpperCase()
    : "CNY";

  // Validate amount
  const cleanAmount = amount ? Math.max(0, parseFloat(String(amount))) : null;
  if (cleanAmount !== null && (isNaN(cleanAmount) || cleanAmount > 999999)) {
    return res.status(400).json({ error: "Invalid amount" });
  }

  const displayName = is_anonymous ? "Anonymous" : String(name || "").trim().slice(0, 50);

  try {
    const id = genId();
    await run(
      `INSERT INTO sponsors (id, name, avatar_url, amount, currency, message, sponsor_date, is_anonymous, is_visible, platform)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        id,
        displayName,
        null,
        cleanAmount,
        cleanCurrency,
        message ? String(message).trim().slice(0, 200) : null,
        new Date().toISOString().slice(0, 10),
        !!is_anonymous,
        false,
        platform ? String(platform).slice(0, 30) : null,
      ]
    );
    return res.json({ ok: true, id });
  } catch (err: any) {
    console.error("[sponsors/submit] error:", err.message);
    return res.status(500).json({ error: "Submission failed, please try again later" });
  }
}
