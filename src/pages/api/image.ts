import type { NextApiRequest, NextApiResponse } from "next";
import { many } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/image");

const ALLOWED_KEYS = new Set([
  "og_image",
  "og_image_twitter",
  "og_image_wechat",
  "og_image_facebook",
  "og_image_youtube",
  "site_icon_url",
  "sponsor_alipay_qr",
  "sponsor_wechat_qr",
]);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const key = req.query.key as string;
  if (!key || !ALLOWED_KEYS.has(key)) {
    return res.status(400).json({ error: "Invalid key" });
  }

  try {
    const rows = await many<{ value: string }>(
      "SELECT value FROM site_settings WHERE key = $1 LIMIT 1",
      [key]
    );
    const value = rows[0]?.value || "";

    if (!value) return res.status(404).json({ error: "Not found" });

    if (value.startsWith("data:image/")) {
      const match = value.match(/^data:(image\/[\w+]+);base64,(.+)$/);
      if (!match) return res.status(400).json({ error: "Invalid data URL" });
      const contentType = match[1];
      const buffer = Buffer.from(match[2], "base64");
      res.setHeader("Content-Type", contentType);
      res.setHeader("Cache-Control", "public, max-age=86400");
      return res.send(buffer);
    }

    // Regular URL — redirect
    return res.redirect(302, value);
  } catch (e: any) {
    logger.error("[image]", e);
    return res.status(500).json({ error: "Image generation failed" });
  }
}
