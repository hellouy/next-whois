import { run, isDbReady, one } from "@/lib/db-query";
import { randomBytes } from "crypto";
import { scoreDomain, shouldAlertAdmin } from "@/lib/domain-value";
import { sendEmail, highValueAlertHtml, getSiteLabel } from "@/lib/email";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { checkHotPrefix } from "@/lib/server/hot-prefix-cache";
import { analyzeDomainWithAi } from "@/lib/server/domain-value-ai";
import { WhoisAnalyzeResult } from "@/lib/whois/types";
import { DnsProbeResult } from "@/lib/whois/dns-check";

export function detectQueryType(query: string): "domain" | "ipv4" | "ipv6" | "asn" | "cidr" {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query)) return "ipv4";
  if (/^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(query) || /::/.test(query) && /[0-9a-fA-F:]/.test(query)) return "ipv6";
  if (/^(AS|as)\d+$/.test(query)) return "asn";
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(query)) return "cidr";
  return "domain";
}

export function deriveRegStatus(
  result: WhoisAnalyzeResult,
  dnsProbe?: DnsProbeResult,
): string | null {
  if (result.expirationDate && result.expirationDate !== "Unknown") return "registered";
  if (result.registrar && result.registrar !== "Unknown") return "registered";
  if (result.status?.some(s => s.status?.toLowerCase().includes("active"))) return "registered";
  if (dnsProbe?.registrationStatus === "unregistered") return "unregistered";
  if (dnsProbe?.registrationStatus === "registered") return "registered";
  return null;
}

export function computeValueTier(
  query: string,
  queryType: string,
  regStatus: string | null,
): "high" | "valuable" | "normal" {
  if (queryType !== "domain" || regStatus !== "unregistered") return "normal";
  const result = scoreDomain(query, queryType);
  if (!result) return "normal";
  if (result.score >= 55) return "high";
  if (result.score >= 35) return "valuable";
  return "normal";
}

export async function maybeSendHighValueAlert(
  query: string,
  queryType: string,
  regStatus: string,
  checkedByEmail?: string | null,
) {
  const scoreResult = scoreDomain(query, queryType);
  const [hotPrefixMatch] = await Promise.all([
    checkHotPrefix(query.substring(0, query.lastIndexOf(".")) || query).catch(() => null),
  ]);

  const shouldAlert = shouldAlertAdmin(query, queryType, regStatus) || !!hotPrefixMatch;
  if (!shouldAlert) return;

  const recent = await one<{ count: string }>(
    `SELECT COUNT(*) AS count FROM search_history
     WHERE LOWER(query) = LOWER($1) AND reg_status = 'unregistered'
     AND created_at >= NOW() - INTERVAL '24 hours'`,
    [query],
  );
  if (parseInt(recent?.count ?? "0") > 0) return;

  if (!scoreResult) return;

  let aiSummary: string | null = null;
  if (scoreResult.score >= 55 || hotPrefixMatch) {
    try {
      const aiResult = await Promise.race([
        analyzeDomainWithAi(query),
        new Promise<null>((_, reject) => setTimeout(() => reject(new Error("timeout")), 8000)),
      ]) as Awaited<ReturnType<typeof analyzeDomainWithAi>> | null;
      if (aiResult && typeof aiResult === "object" && "summary" in aiResult) {
        aiSummary = (aiResult as { summary?: string }).summary ?? null;
      }
    } catch {
      // AI unavailable — proceed without it
    }
  }

  const siteName = await getSiteLabel().catch(() => "X.RW");
  const html = highValueAlertHtml({
    domain: query,
    score: scoreResult.score,
    tier: scoreResult.tier,
    reasons: scoreResult.reasons,
    isAlertKeyword: scoreResult.isAlertKeyword,
    isNumericOnly: scoreResult.isNumericOnly,
    checkedBy: checkedByEmail ?? null,
    breakdown: scoreResult.breakdown,
    hotPrefix: hotPrefixMatch ? {
      prefix: hotPrefixMatch.prefix.prefix,
      category: hotPrefixMatch.prefix.category,
      weight: hotPrefixMatch.prefix.weight,
      matchType: hotPrefixMatch.matchType,
      saleExamples: hotPrefixMatch.prefix.sale_examples,
      notes: hotPrefixMatch.prefix.notes,
    } : null,
    aiSummary,
    siteName,
  });

  const subjectPrefix = hotPrefixMatch
    ? `🔥 热门前缀可用`
    : scoreResult.isAlertKeyword
    ? "⚡ 特殊关键词可用"
    : "💎 高价值域名可用";

  await sendEmail({
    to: ADMIN_EMAIL,
    subject: `${subjectPrefix}：${query}（评分 ${scoreResult.score}${hotPrefixMatch ? ` · 前缀:${hotPrefixMatch.prefix.prefix}` : ""}）`,
    html,
  }).catch(err => console.error("[high-value-alert]", err.message));
}

// Prune anonymous search_history records older than 30 days (1% of requests).
// Anonymous rows have no user retention value; they are used only for aggregate stats.
async function maybePruneAnonymous() {
  if (Math.random() > 0.01) return;
  try {
    await run(
      `DELETE FROM search_history WHERE user_id IS NULL AND created_at < NOW() - INTERVAL '30 days'`,
    );
  } catch {}
}

export async function saveSearchRecord(
  query: string,
  result: WhoisAnalyzeResult,
  dnsProbe?: DnsProbeResult,
  userId?: string | null,
  checkedByEmail?: string | null,
): Promise<void> {
  if (!(await isDbReady())) return;
  try {
    const cleanQuery = query.toLowerCase().trim();
    const queryType  = detectQueryType(cleanQuery);
    const regStatus  = deriveRegStatus(result, dnsProbe);
    const valueTier  = computeValueTier(cleanQuery, queryType, regStatus);
    const expDate    = result.expirationDate && result.expirationDate !== "Unknown" ? result.expirationDate : null;
    const remDays    = result.remainingDays ?? null;

    if (regStatus === "unregistered") {
      maybeSendHighValueAlert(cleanQuery, queryType, regStatus, checkedByEmail).catch(() => {});
    }

    // Always insert a fresh record for every search event — both logged-in and anonymous.
    // This ensures every query is counted in admin stats regardless of who performed it.
    // The user history API uses DISTINCT ON to deduplicate for the user-facing display.
    await run(
      `INSERT INTO search_history
         (id, user_id, query, query_type, reg_status, expiration_date, remaining_days, value_tier)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [randomBytes(8).toString("hex"), userId ?? null, cleanQuery, queryType, regStatus, expDate, remDays, valueTier],
    );

    // Opportunistically prune old anonymous records (fire-and-forget)
    if (!userId) maybePruneAnonymous().catch(() => {});
  } catch (err: any) {
    console.error("[save-search-record] DB write failed:", err?.message ?? err);
  }
}
