import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { checkRateLimit } from "@/lib/rate-limit";
import { one, run, isDbReady } from "@/lib/db-query";

/** Basic domain format validation (supports IDN punycode, rejects obvious garbage) */
function isValidDomain(d: string): boolean {
  if (!d || d.length > 253) return false;
  if (!d.includes(".")) return false;
  if (d.startsWith(".") || d.endsWith(".")) return false;
  if (d.includes("..")) return false;
  const labels = d.split(".");
  const tld = labels[labels.length - 1];
  if (tld.length < 2) return false;
  return labels.every(l =>
    l.length > 0 && l.length <= 63 &&
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(l)
  );
}

// Free-tier limits enforced server-side (mirrors UI in stamp.tsx / dashboard.tsx)
const FREE_TAG_NAME_MAX = 5;
const MEMBER_TAG_NAME_MAX = 20;
const FREE_TAG_STYLES   = ["personal"];
const FREE_CARD_THEMES  = ["app"];
const ALLOWED_TAG_STYLES   = ["personal","official","brand","verified","partner","dev","warning","premium"];
const ALLOWED_CARD_THEMES  = ["app","gradient","celebrate","split","flash","neon"];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(ip, 5);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again later" });

  const { domain, tagName, tagStyle, cardTheme, link, description, nickname, email } = req.body;
  if (!domain || !tagName || !nickname || !email)
    return res.status(400).json({ error: "Missing required fields" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Database unavailable" });

  // ── Determine membership status from DB (never trust client JWT alone) ───────
  const session = await getServerSession(req, res, authOptions);
  let isMember = false;
  if (session?.user?.email) {
    const userRow = await one<{ subscription_access: boolean; subscription_expires_at: string | null }>(
      "SELECT subscription_access, subscription_expires_at FROM users WHERE email = $1",
      [session.user.email],
    ).catch(() => null);
    // Check both access flag and expiry
    const expired = userRow?.subscription_expires_at
      ? new Date(userRow.subscription_expires_at) < new Date()
      : false;
    isMember = !!(userRow?.subscription_access && !expired);
  }

  // ── Enforce member-only feature gates ───────────────────────────────────────
  const rawTagName  = String(tagName).trim();
  const rawTagStyle = String(tagStyle || "personal");
  const rawCardTheme = String(cardTheme || "app");

  // Tag name length gate
  const maxTagLen = isMember ? MEMBER_TAG_NAME_MAX : FREE_TAG_NAME_MAX;
  if (rawTagName.length > maxTagLen) {
    return res.status(403).json({
      error: isMember
        ? `Tag name cannot exceed ${MEMBER_TAG_NAME_MAX} characters`
        : `Free users are limited to ${FREE_TAG_NAME_MAX} characters. Upgrade to unlock longer names`,
      code: "MEMBER_REQUIRED",
    });
  }

  // Tag style gate — only "personal" is free
  const resolvedTagStyle = ALLOWED_TAG_STYLES.includes(rawTagStyle) ? rawTagStyle : "personal";
  if (!isMember && !FREE_TAG_STYLES.includes(resolvedTagStyle)) {
    return res.status(403).json({
      error: "Premium tag styles require a membership",
      code: "MEMBER_REQUIRED",
    });
  }

  // Card theme gate — only "app" is free
  const resolvedCardTheme = ALLOWED_CARD_THEMES.includes(rawCardTheme) ? rawCardTheme : "app";
  if (!isMember && !FREE_CARD_THEMES.includes(resolvedCardTheme)) {
    return res.status(403).json({
      error: "Premium card themes require a membership",
      code: "MEMBER_REQUIRED",
    });
  }

  const cleanDomain   = String(domain).toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/$/, "").replace(/\/.*$/, "");
  if (!isValidDomain(cleanDomain)) {
    return res.status(400).json({ error: "域名格式不正确，请输入有效的域名（如 example.com）" });
  }
  const cleanTagName  = rawTagName.slice(0, maxTagLen);
  const cleanTagStyle  = resolvedTagStyle;
  const cleanCardTheme = resolvedCardTheme;
  const cleanLink     = String(link || "").trim() || null;
  const cleanDesc     = String(description || "").trim().slice(0, 300) || null;
  const cleanNickname = String(nickname).trim().slice(0, 30);
  const cleanEmail    = String(email).trim();

  const existing = await one<{ id: string; verify_token: string }>(
    `SELECT id, verify_token FROM stamps
     WHERE domain = $1 AND email = $2 AND verified = false
     ORDER BY created_at DESC LIMIT 1`,
    [cleanDomain, cleanEmail],
  );

  if (existing) {
    await run(
      `UPDATE stamps
       SET tag_name = $1, tag_style = $2, link = $3, description = $4, nickname = $5, card_theme = $6
       WHERE id = $7`,
      [cleanTagName, cleanTagStyle, cleanLink, cleanDesc, cleanNickname, cleanCardTheme, existing.id],
    );
    return res.status(200).json({
      id: existing.id,
      domain: cleanDomain,
      verifyToken: existing.verify_token,
      txtRecord: `_next-whois.${cleanDomain}`,
      txtValue: `next-whois-verify=${existing.verify_token}`,
      reused: true,
    });
  }

  const token = randomBytes(16).toString("hex");
  const id    = randomBytes(8).toString("hex");

  try {
    await run(
      `INSERT INTO stamps
         (id, domain, tag_name, tag_style, card_theme, link, description, nickname, email, verify_token, verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)`,
      [id, cleanDomain, cleanTagName, cleanTagStyle, cleanCardTheme, cleanLink, cleanDesc, cleanNickname, cleanEmail, token],
    );
  } catch (err: any) {
    console.error("[stamp/submit] Write error:", err.message);
    return res.status(500).json({ error: "Database write failed, please try again later" });
  }

  return res.status(200).json({
    id, domain: cleanDomain, verifyToken: token,
    txtRecord: `_next-whois.${cleanDomain}`,
    txtValue: `next-whois-verify=${token}`,
  });
}
