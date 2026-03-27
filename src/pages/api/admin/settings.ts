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

const ALLOWED_KEYS = new Set(Object.keys(DEFAULT_SETTINGS));
const SERVER_ONLY_KEYS = new Set(["captcha_secret_key", "smtp_pass"]);

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
      const admin = await isAdmin(req, res);
      const rows = await getCachedRows();
      const settings: Record<string, string> = {};
      for (const row of rows) {
        if (ALLOWED_KEYS.has(row.key)) {
          if (!SERVER_ONLY_KEYS.has(row.key) || admin) {
            settings[row.key] = row.value;
          }
        }
      }
      res.setHeader("Cache-Control", "private, no-store");
      return res.json({ settings: { ...DEFAULT_SETTINGS, ...settings } });
    } catch {
      res.setHeader("Cache-Control", "private, no-store");
      return res.json({ settings: DEFAULT_SETTINGS });
    }
  }

  if (req.method === "PUT") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const body = req.body as Partial<SiteSettings>;
    try {
      const allowed = Object.keys(DEFAULT_SETTINGS) as (keyof SiteSettings)[];
      for (const key of allowed) {
        if (key in body) {
          await run(
            `INSERT INTO site_settings (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
            [key, String(body[key] ?? "")]
          );
        }
      }
      invalidateCache();
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, PUT");
  res.status(405).json({ error: "Method not allowed" });
}
