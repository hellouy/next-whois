import { randomBytes } from "crypto";
import { one, run } from "@/lib/db-query";
import type { NextApiRequest, NextApiResponse } from "next";

export type KeyScope = "api" | "subscription" | "all";

export interface AccessKey {
  id: string;
  key: string;
  label: string | null;
  scope: KeyScope;
  is_active: boolean;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  use_count: number;
}

export function generateKey(): string {
  return "rwh_" + randomBytes(20).toString("hex");
}

export function generateId(): string {
  return randomBytes(8).toString("hex");
}

let _requireCache: { value: boolean; ts: number } | null = null;
const CACHE_TTL_MS = 30_000;

export function invalidateKeyRequireCache() {
  _requireCache = null;
}

export async function isApiKeyRequired(): Promise<boolean> {
  const now = Date.now();
  if (_requireCache && now - _requireCache.ts < CACHE_TTL_MS) {
    return _requireCache.value;
  }
  try {
    const row = await one<{ value: string }>(
      "SELECT value FROM site_settings WHERE key = 'require_api_key'",
    );
    const value = row?.value === "1";
    _requireCache = { value, ts: now };
    return value;
  } catch {
    return false;
  }
}

export async function validateApiKey(
  rawKey: string,
  neededScope: KeyScope = "api",
): Promise<{ valid: boolean; reason?: string }> {
  if (!rawKey?.startsWith("rwh_")) return { valid: false, reason: "格式无效" };

  try {
    const row = await one<AccessKey>(
      "SELECT * FROM access_keys WHERE key = $1",
      [rawKey],
    );
    if (!row) return { valid: false, reason: "Key 不存在" };
    if (!row.is_active) return { valid: false, reason: "Key 已停用" };
    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return { valid: false, reason: "Key 已过期" };
    }
    const scope = row.scope as KeyScope;
    const scopeCovers =
      scope === "all" ||
      scope === neededScope ||
      (neededScope === "api" && scope === "api") ||
      (neededScope === "subscription" && scope === "subscription");
    if (!scopeCovers) return { valid: false, reason: "Key 权限不足" };

    // Update usage stats without blocking the response
    run(
      "UPDATE access_keys SET last_used_at = NOW(), use_count = use_count + 1 WHERE id = $1",
      [row.id],
    ).catch(() => {});

    return { valid: true };
  } catch {
    return { valid: false, reason: "验证失败" };
  }
}

export function extractApiKey(req: NextApiRequest): string | null {
  const header = req.headers["x-api-key"];
  if (header && typeof header === "string") return header.trim();
  const query = req.query.key;
  if (query && typeof query === "string") return query.trim();
  return null;
}

/**
 * Returns true when the request comes from the same site (same-origin).
 * The browser sends an `Origin` or `Referer` header whose host matches the
 * server's `Host` header for same-origin requests — external callers will
 * either omit it or send a different origin.  This lets the site's own
 * client-side pages call /api/lookup without an API key even when the admin
 * has enabled API-key enforcement for external consumers.
 */
export function isSameOriginRequest(req: NextApiRequest): boolean {
  const host = req.headers["host"];
  if (!host) return false;

  // Check Origin header first (set by fetch() in modern browsers)
  const origin = req.headers["origin"];
  if (origin && typeof origin === "string") {
    try {
      const originHost = new URL(origin).host;
      return originHost === host;
    } catch { /* ignore malformed origin */ }
  }

  // Fallback: check Referer header
  const referer = req.headers["referer"];
  if (referer && typeof referer === "string") {
    try {
      const refHost = new URL(referer).host;
      return refHost === host;
    } catch { /* ignore malformed referer */ }
  }

  return false;
}

export async function enforceApiKey(
  req: NextApiRequest,
  res: NextApiResponse,
  scope: KeyScope = "api",
): Promise<boolean> {
  const required = await isApiKeyRequired();
  if (!required) return true;

  // Always allow requests that originate from the same site (e.g. the query
  // page fetching /api/lookup client-side) even when external API key
  // enforcement is enabled.
  if (isSameOriginRequest(req)) return true;

  const key = extractApiKey(req);
  if (!key) {
    res.status(401).json({
      error: "此接口需要 API Key。请在请求头中添加 X-API-Key: <your_key> 或在 URL 中添加 ?key=<your_key>",
    });
    return false;
  }

  const { valid, reason } = await validateApiKey(key, scope);
  if (!valid) {
    res.status(403).json({ error: `API Key 无效：${reason}` });
    return false;
  }

  return true;
}
