import type { NextApiRequest, NextApiResponse } from "next";
import { many, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

const DEFAULT_BRAND_NAME = "RDAP+WHOIS";
const DEFAULT_TAGLINE    = "WHOIS / RDAP · Domain Lookup Tool";

export { DEFAULT_BRAND_NAME, DEFAULT_TAGLINE };

interface OgConfig {
  enabled_styles: number[];
  brand_name: string;
  tagline: string;
}

let _cache: OgConfig | null = null;
let _cacheTime = 0;
const CACHE_TTL = 5 * 60 * 1000;

export const TOTAL_STYLES = 8;

export function parseEnabledStyles(val: string | undefined | null): number[] {
  if (!val || val.trim() === "") {
    return Array.from({ length: TOTAL_STYLES }, (_, i) => i);
  }
  const parsed = val
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => !isNaN(n) && n >= 0 && n < TOTAL_STYLES);
  return parsed.length > 0 ? parsed : Array.from({ length: TOTAL_STYLES }, (_, i) => i);
}

export function invalidateOgConfigCache() {
  _cacheTime = 0;
  _cache = null;
}

async function loadConfig(): Promise<OgConfig> {
  const rows = await many<{ key: string; value: string }>(
    `SELECT key, value FROM site_settings WHERE key IN ('og_enabled_styles','og_brand_name','og_tagline')`,
  );
  const map: Record<string, string> = {};
  for (const r of rows) map[r.key] = r.value;
  return {
    enabled_styles: parseEnabledStyles(map.og_enabled_styles),
    brand_name: map.og_brand_name || DEFAULT_BRAND_NAME,
    tagline: map.og_tagline || DEFAULT_TAGLINE,
  };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    try {
      if (!_cache || Date.now() - _cacheTime > CACHE_TTL) {
        _cache = await loadConfig();
        _cacheTime = Date.now();
      }
      res.setHeader("Cache-Control", "public, max-age=300");
      return res.json(_cache);
    } catch {
      return res.json({
        enabled_styles: Array.from({ length: TOTAL_STYLES }, (_, i) => i),
        brand_name: DEFAULT_BRAND_NAME,
        tagline: DEFAULT_TAGLINE,
      });
    }
  }

  if (req.method === "PUT") {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const { brand_name, tagline } = req.body as { brand_name?: string; tagline?: string };
    try {
      if (brand_name !== undefined) {
        await run(
          `INSERT INTO site_settings (key, value, updated_at) VALUES ('og_brand_name', $1, NOW())
           ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
          [brand_name.trim() || DEFAULT_BRAND_NAME],
        );
      }
      if (tagline !== undefined) {
        await run(
          `INSERT INTO site_settings (key, value, updated_at) VALUES ('og_tagline', $1, NOW())
           ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
          [tagline.trim() || DEFAULT_TAGLINE],
        );
      }
      invalidateOgConfigCache();
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).end();
}
