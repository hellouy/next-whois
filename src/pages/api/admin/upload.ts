import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";

export const config = { api: { bodyParser: { sizeLimit: "10mb" } } };

const ALLOWED_MIME_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/avif",
]);

function validateImageMagicBytes(buf: Buffer, mime: string): boolean {
  if (buf.length < 12) return false;
  switch (mime) {
    case "image/png":
      return buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
    case "image/jpeg":
      return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
    case "image/gif":
      return buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38;
    case "image/webp":
      return (
        buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
        buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50
      );
    case "image/avif":
      return buf[4] === 0x66 && buf[5] === 0x74 && buf[6] === 0x79 && buf[7] === 0x70;
    default:
      return false;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const admin = await requireAdmin(req, res);
  if (!admin) return;

  try {
    const { dataUrl } = req.body as { dataUrl?: string; hint?: string };
    if (!dataUrl || !dataUrl.startsWith("data:image/")) {
      return res.status(400).json({ error: "Invalid image data" });
    }

    const match = dataUrl.match(/^data:(image\/(\w+));base64,(.+)$/);
    if (!match) return res.status(400).json({ error: "Malformed data URL" });

    const mimeType = match[1].toLowerCase();

    if (!ALLOWED_MIME_TYPES.has(mimeType)) {
      return res.status(415).json({
        error: `Unsupported image type '${mimeType}'. Allowed: PNG, JPEG, GIF, WebP, AVIF`,
      });
    }

    const base64 = match[3];
    const buffer = Buffer.from(base64, "base64");

    if (buffer.byteLength > 8 * 1024 * 1024) {
      return res.status(413).json({ error: "File too large (max 8 MB)" });
    }

    if (!validateImageMagicBytes(buffer, mimeType)) {
      return res.status(400).json({
        error: "File content does not match declared type. Upload rejected.",
      });
    }

    return res.status(200).json({ url: dataUrl });
  } catch (e: any) {
    return res.status(500).json({ error: e.message || "Upload failed" });
  }
}
