import type { NextApiRequest, NextApiResponse } from "next";
import { sendEmail, feedbackHtml, getSiteLabel } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { run, isDbReady } from "@/lib/db-query";
import { randomBytes } from "crypto";

const ISSUE_LABELS: Record<string, string> = {
  // Domain / WHOIS
  inaccurate:      "数据不准确",
  incomplete:      "数据不完整",
  outdated:        "数据已过期",
  parse_error:     "解析错误",
  // DNS
  resolve_failed:  "查询失败 / 超时",
  wrong_result:    "结果不正确",
  missing_record:  "记录缺失",
  // SSL
  cert_error:      "证书错误 / 不受信任",
  chain_error:     "证书链错误",
  expired_wrong:   "过期时间显示有误",
  // IP / ASN
  wrong_location:  "归属地不准确",
  wrong_isp:       "ISP / 运营商有误",
  wrong_asn:       "ASN 信息有误",
  // General
  feature_request: "功能建议",
  bug_report:      "程序错误",
  question:        "使用问题",
  other:           "其他",
};

const VALID_ISSUE_KEYS = new Set(Object.keys(ISSUE_LABELS));

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // ── Rate limit: 3 submissions per IP per minute ──────────────────────────
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();

  const rl = await checkRateLimit(ip, 3);
  if (!rl.ok) {
    return res.status(429).json({ error: "Too many submissions, please try again later" });
  }

  const { query, queryType, issueTypes, description, email, _hp, _t } = req.body;

  // ── Honeypot: bots fill hidden fields, real users don't ──────────────────
  if (_hp && String(_hp).trim().length > 0) {
    // Silently accept to not reveal detection
    return res.status(200).json({ ok: true });
  }

  // ── Timing: reject if submitted in under 2 seconds (likely a bot) ────────
  const submittedAt = Number(_t) || 0;
  const elapsed = Date.now() - submittedAt;
  if (submittedAt > 0 && elapsed < 2000) {
    return res.status(200).json({ ok: true });
  }

  // ── Basic validation ─────────────────────────────────────────────────────
  if (!query || typeof query !== "string" || query.trim().length === 0) {
    return res.status(400).json({ error: "Missing query target" });
  }
  if (!Array.isArray(issueTypes) || issueTypes.length === 0) {
    return res.status(400).json({ error: "Please select an issue type" });
  }

  const validatedIssues = (issueTypes as string[]).filter((k) => VALID_ISSUE_KEYS.has(k));
  if (validatedIssues.length === 0) {
    return res.status(400).json({ error: "Invalid issue type" });
  }

  const cleanQuery       = String(query).trim().slice(0, 253);
  const cleanDescription = description ? String(description).trim().slice(0, 500) : "";
  const cleanEmail       = email ? String(email).trim().slice(0, 254) : "";
  const issueLabels      = validatedIssues.map((k) => ISSUE_LABELS[k]).join("、");
  const ts               = new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });

  const siteName = await getSiteLabel().catch(() => "WHOIS");
  await sendEmail({
    to: ADMIN_EMAIL,
    subject: `[反馈] ${cleanQuery} — ${issueLabels}`,
    html: feedbackHtml({
      query: cleanQuery,
      queryType: String(queryType || "general"),
      issueLabels,
      description: cleanDescription || undefined,
      email: cleanEmail || undefined,
      ip,
      ts,
      siteName,
    }),
  });

  if (await isDbReady()) {
    const id = randomBytes(8).toString("hex");
    await run(
      `INSERT INTO feedback (id, query, query_type, issue_types, description, email)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        id,
        cleanQuery,
        String(queryType || "general"),
        validatedIssues.join(","),
        cleanDescription || null,
        cleanEmail || null,
      ],
    ).catch(() => {});
  }

  return res.status(200).json({ ok: true });
}
