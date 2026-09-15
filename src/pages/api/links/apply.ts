import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { one, many, run } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import {
  getSiteLabel,
  sendEmail,
  sendEmailDirect,
  linkApplyAdminHtml,
  linkApplyResultHtml,
} from "@/lib/email";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { resolveSiteIdentity } from "@/lib/server/site-identity";
import { checkBacklink } from "@/lib/server/backlink-check";
import { buildBadges } from "@/lib/server/badge";
import { createLogger } from "@/lib/logger";

export const maxDuration = 30;

const logger = createLogger("api/links/apply");
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

function detectLocale(req: NextApiRequest): "zh" | "en" {
  return (req.headers["accept-language"] || "").toLowerCase().startsWith("zh") ? "zh" : "en";
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const siteLabel = await getSiteLabel().catch(() => "WHOIS");
    const identity = await resolveSiteIdentity();
    const cats = await many<{ category: string }>(
      "SELECT DISTINCT category FROM friendly_links WHERE category IS NOT NULL AND category <> '' ORDER BY category"
    ).catch(() => []);
    return res.json({
      siteLabel,
      siteUrl: identity.url,
      categories: cats.map(c => c.category),
      badge: buildBadges(identity),
    });
  }

  if (req.method !== "POST") return res.status(405).end();

  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();

  const rl = await checkRateLimit(ip, 3);
  if (!rl.ok) {
    return res.status(429).json({ error: "Too many submissions, please try again later" });
  }

  const { name, url, description, category, email, _hp, _t } = req.body;

  // Honeypot: bots fill hidden fields, real users don't
  if (_hp && String(_hp).trim().length > 0) {
    return res.status(200).json({ ok: true });
  }

  // Timing: reject if submitted in under 2 seconds (likely a bot)
  const submittedAt = Number(_t) || 0;
  if (submittedAt > 0 && Date.now() - submittedAt < 2000) {
    return res.status(200).json({ ok: true });
  }

  const cleanName = String(name || "").trim().slice(0, 80);
  const cleanUrl = String(url || "").trim().slice(0, 253);
  const cleanDesc = description ? String(description).trim().slice(0, 500) : "";
  const cleanCat = category ? String(category).trim().slice(0, 40) : "";
  const cleanEmail = String(email || "").trim().slice(0, 254).toLowerCase();

  if (!cleanName) return res.status(400).json({ error: "请填写站点名称" });
  if (!cleanEmail || !EMAIL_RE.test(cleanEmail)) {
    return res.status(400).json({ error: "邮箱格式不正确" });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(cleanUrl);
    if (!/^https?:$/.test(parsedUrl.protocol)) throw new Error("unsupported");
    if (!parsedUrl.hostname || hostOf(cleanUrl).length === 0) throw new Error("no-host");
  } catch {
    return res.status(400).json({ error: "URL 格式不正确" });
  }

  // ── Duplicate guard: same host already listed or under review ────────────
  const host = hostOf(cleanUrl);
  const dupLink = await many<{ id: number }>(
    "SELECT id FROM friendly_links WHERE active AND url ILIKE $1 LIMIT 1",
    [`%${host}%`],
  ).catch(() => []);
  const dupApply = await many<{ id: string }>(
    "SELECT id FROM friendly_link_applications WHERE status IN ('review','approved') AND url ILIKE $1 LIMIT 1",
    [`%${host}%`],
  ).catch(() => []);
  if (dupLink.length > 0 || dupApply.length > 0) {
    return res.status(400).json({ error: "该站点已申请或已上链，无需重复提交" });
  }

  const id = randomBytes(8).toString("hex");
  const ts = new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
  const siteName = await getSiteLabel().catch(() => "WHOIS");
  const identity = await resolveSiteIdentity();

  try {
    await run(
      `INSERT INTO friendly_link_applications (id, name, url, description, category, email, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'review')`,
      [id, cleanName, cleanUrl, cleanDesc || null, cleanCat || null, cleanEmail],
    );
  } catch (err: unknown) {
    logger.error("[links/apply] insert failed:", err instanceof Error ? err.message : err);
    return res.status(500).json({ error: "提交失败，请稍后再试" });
  }

  // ── Auto backlink check ────────────────────────────────────────────────────
  const backlink = await checkBacklink(cleanUrl).catch(() => ({
    found: false,
    pages: ([] as { url: string; found: boolean }[]),
    checkedAt: new Date().toISOString(),
  }));

  let status: string = backlink.found ? "approved" : "review";
  let autoApproved = false;
  let linkId: number | null = null;

  if (backlink.found) {
    autoApproved = true;
    const created = await one<{ id: number }>(
      `INSERT INTO friendly_links (name, url, description, category)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [cleanName, cleanUrl, cleanDesc || null, cleanCat || null],
    ).catch(() => null);
    if (!created) status = "review"; // conservative: fall back to manual review
    else {
      linkId = created.id;
    }
  }

  await run(
    `UPDATE friendly_link_applications
     SET status=$1, auto_approved=$2, backlink_pages=$3, link_id=$4, reviewed_at=$5
     WHERE id=$6`,
    [
      status,
      autoApproved,
      JSON.stringify({ found: backlink.found, pages: backlink.pages }),
      linkId,
      autoApproved ? new Date().toISOString() : null,
      id,
    ],
  ).catch((err: unknown) => {
    logger.error("[links/apply] update failed:", err instanceof Error ? err.message : err);
  });

  // ── Notifications ──────────────────────────────────────────────────────────
  if (ADMIN_EMAIL) {
    const summary = backlink.found
      ? "检出本站链接，已自动通过"
      : backlink.pages.length > 0
        ? `未检出本站链接（已抓取 ${backlink.pages.length} 页），转人工`
        : "无法抓取目标站点，转人工";
    await sendEmailDirect(
      ADMIN_EMAIL,
      `[友链申请] ${cleanName} — ${summary}`,
      linkApplyAdminHtml({
        name: cleanName,
        url: cleanUrl,
        email: cleanEmail,
        category: cleanCat || undefined,
        description: cleanDesc || undefined,
        autoApproved,
        backlinkSummary: summary,
        ts,
        siteName,
      }),
    ).catch((err: unknown) => {
      logger.error("[links/apply] admin email failed:", err instanceof Error ? err.message : err);
    });
  }

  await sendEmail({
    to: cleanEmail,
    subject: `[${siteName}] 友链申请${autoApproved ? "已通过" : "已收到"}`,
    html: linkApplyResultHtml({
      name: cleanName,
      approved: autoApproved,
      reason: undefined,
      siteName,
      locale: detectLocale(req),
    }),
  }).catch((err: unknown) => {
    logger.error("[links/apply] user email failed:", err instanceof Error ? err.message : err);
  });

  return res.status(201).json({
    ok: true,
    status,
    autoApproved,
    backlink,
    badge: buildBadges(identity),
    siteLabel: siteName,
  });
}