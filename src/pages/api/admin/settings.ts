import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { isAdminEmail, invalidateAdminEmailCache } from "@/lib/admin-server";
import { DEFAULT_SETTINGS, type SiteSettings } from "@/lib/site-settings";
import {
  isRedisAvailable,
  getJsonRedisValue,
  setJsonRedisValue,
  deleteRedisValue,
} from "@/lib/server/redis";
import { invalidateSettingsCache } from "@/lib/server/site-settings-server";

const ALLOWED_KEYS = new Set(Object.keys(DEFAULT_SETTINGS));
const SERVER_ONLY_KEYS = new Set([
  "captcha_secret_key",
  "captcha_turnstile_secret_key",
  "captcha_hcaptcha_secret_key",
  "captcha_mtcaptcha_secret_key",
  "smtp_pass",
  "resend_api_key",
  "payment_stripe_sk",
  "payment_stripe_webhook_secret",
  "payment_xunhupay_secret",
  "payment_alipay_private_key",
  "payment_paypal_client_secret",
  "notify_bark_url",
  "notify_telegram_token",
  "notify_telegram_chat_id",
  "notify_dingding_webhook",
  "notify_feishu_webhook",
  "notify_wecom_webhook",
  "notify_generic_webhook",
  "expireddomains_password",
]);

let _rowsCache: { rows: { key: string; value: string }[]; ts: number } | null = null;
const ROWS_CACHE_TTL = 30_000;
const REDIS_SETTINGS_KEY = "site_settings:rows:v1";
const REDIS_SETTINGS_TTL = 300; // 5 minutes — settings rarely change

async function getCachedRows(): Promise<{ key: string; value: string }[]> {
  const now = Date.now();
  // L1: in-process
  if (_rowsCache && now - _rowsCache.ts < ROWS_CACHE_TTL) return _rowsCache.rows;
  // L2: Redis
  if (isRedisAvailable()) {
    const cached = await getJsonRedisValue<{ key: string; value: string }[]>(REDIS_SETTINGS_KEY);
    if (cached) {
      _rowsCache = { rows: cached, ts: now };
      return cached;
    }
  }
  // L3: DB
  const rows = await many<{ key: string; value: string }>("SELECT key, value FROM site_settings");
  _rowsCache = { rows, ts: now };
  if (isRedisAvailable()) {
    setJsonRedisValue(REDIS_SETTINGS_KEY, rows, REDIS_SETTINGS_TTL).catch(() => {});
  }
  return rows;
}

function invalidateCache() {
  _rowsCache = null;
  invalidateAdminEmailCache();
  invalidateSettingsCache(); // clear per-key server-side cache
  if (isRedisAvailable()) {
    deleteRedisValue(REDIS_SETTINGS_KEY).catch(() => {});
  }
}

async function isAdmin(req: NextApiRequest, res: NextApiResponse): Promise<boolean> {
  try {
    const session = await getServerSession(req, res, authOptions);
    const email = (session?.user as any)?.email;
    return await isAdminEmail(email);
  } catch {
    return false;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    try {
      const [admin, rows] = await Promise.all([isAdmin(req, res), getCachedRows()]);
      const settings: Record<string, string> = {};
      for (const row of rows) {
        if (ALLOWED_KEYS.has(row.key)) {
          if (!SERVER_ONLY_KEYS.has(row.key) || admin) {
            settings[row.key] = row.value;
          }
        }
      }
      res.setHeader(
        "Cache-Control",
        admin ? "private, no-store" : "private, max-age=60, stale-while-revalidate=300",
      );
      return res.json({ settings: { ...DEFAULT_SETTINGS, ...settings } });
    } catch {
      res.setHeader("Cache-Control", "private, max-age=60, stale-while-revalidate=300");
      return res.json({ settings: DEFAULT_SETTINGS });
    }
  }

  if (req.method === "PUT") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const body = req.body as Partial<SiteSettings>;
    try {
      const keys = (Object.keys(DEFAULT_SETTINGS) as (keyof SiteSettings)[]).filter(k => k in body);
      if (keys.length > 0) {
        // Single multi-row batch upsert — far cheaper than N individual round-trips.
        const placeholders = keys.map((_, i) => `($${i * 2 + 1}, $${i * 2 + 2}, NOW())`).join(", ");
        const values = keys.flatMap(key => [key, String(body[key] ?? "")]);
        await run(
          `INSERT INTO site_settings (key, value, updated_at)
           VALUES ${placeholders}
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
          values,
        );
      }
      invalidateCache();
      return res.json({ ok: true, updated: keys.length });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, PUT");
  res.status(405).json({ error: "Method not allowed" });
}
