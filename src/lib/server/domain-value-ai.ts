/**
 * AI-powered domain value deep analysis.
 * Uses the existing multi-provider AI system (ZhipuAI, Groq, Gemini, etc.)
 * Results are cached in Redis for 7 days to avoid repeated calls.
 */

import { getConfiguredProviders } from "./ai-providers";
import { redis, isRedisAvailable } from "./redis";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/domain-value-ai");

export interface DomainAiAnalysis {
  domain: string;
  marketValue: {
    low: number;
    mid: number;
    high: number;
    currency: "USD";
    note: string;
  };
  useCases: Array<{
    title: string;
    desc: string;
  }>;
  brandPotential: number;       // 0-10
  memorability: number;         // 0-10
  summary: string;
  investmentVerdict: "强烈推荐" | "值得关注" | "一般" | "不推荐";
  verdictColor: string;
  model: string;
  cached: boolean;
  analyzedAt: string;
}

const CACHE_TTL = 7 * 24 * 3600;   // 7 days
const CACHE_PREFIX = "domain_ai_v2:";

function cacheKey(domain: string) {
  return CACHE_PREFIX + domain.toLowerCase();
}

/** Build the prompt for domain analysis */
function buildPrompt(domain: string): string {
  return `You are a professional domain name investment expert and brand consultant with deep knowledge of the global domain market, aftermarket sales, and brand naming strategy.

Analyze the domain name "${domain}" and return a JSON object with the following structure:
{
  "marketValue": {
    "low": <integer USD>,
    "mid": <integer USD>,
    "high": <integer USD>,
    "note": "<1 sentence explaining key value drivers or risks>"
  },
  "useCases": [
    { "title": "<short use case name in Chinese>", "desc": "<1 sentence in Chinese>" },
    { "title": "...", "desc": "..." },
    { "title": "...", "desc": "..." }
  ],
  "brandPotential": <integer 0-10>,
  "memorability": <integer 0-10>,
  "summary": "<2-3 sentences in Chinese summarizing domain value, target audience, and investment outlook>",
  "investmentVerdict": "<one of: 强烈推荐 | 值得关注 | 一般 | 不推荐>"
}

Guidelines:
- marketValue: Estimate realistic aftermarket resale value in USD. Consider length, TLD, keyword trends, comparable sales. Be honest — most domains are worth $100-$5000. Only truly exceptional domains (short, premium TLD, hot keyword) reach $10k+.
- useCases: Provide exactly 3 creative but realistic use cases. Think about who would actually buy this domain.
- brandPotential: How easily can this become a memorable brand? (0=terrible, 10=instantly iconic). Consider pronounceability, uniqueness, and emotional resonance.
- memorability: How easy to remember and type correctly? (0=impossible, 10=perfect recall).
- summary: Write in Chinese. Be specific and insightful, not generic.
- investmentVerdict: 强烈推荐 if score≥80+premium TLD+hot keyword; 值得关注 if interesting but not exceptional; 一般 if average; 不推荐 if poor investment.

Return ONLY valid JSON, no markdown, no explanation.`;
}

/** Parse AI JSON response, tolerant of markdown fences */
function parseAiResponse(text: string): Omit<DomainAiAnalysis, "domain" | "model" | "cached" | "analyzedAt"> | null {
  const cleaned = text
    .replace(/```json\s*/gi, "")
    .replace(/```\s*/gi, "")
    .trim();

  try {
    const obj = JSON.parse(cleaned);

    // Validate required fields
    if (!obj.marketValue || typeof obj.marketValue.low !== "number") return null;
    if (!Array.isArray(obj.useCases) || obj.useCases.length === 0) return null;
    if (typeof obj.brandPotential !== "number") return null;
    if (!obj.summary || !obj.investmentVerdict) return null;

    // Normalise / clamp
    obj.marketValue.low   = Math.max(0, Math.round(obj.marketValue.low));
    obj.marketValue.mid   = Math.max(obj.marketValue.low, Math.round(obj.marketValue.mid ?? ((obj.marketValue.low + obj.marketValue.high) / 2)));
    obj.marketValue.high  = Math.max(obj.marketValue.mid, Math.round(obj.marketValue.high));
    obj.marketValue.currency = "USD";
    obj.marketValue.note  = String(obj.marketValue.note ?? "").slice(0, 120);
    obj.brandPotential    = Math.min(10, Math.max(0, Math.round(obj.brandPotential)));
    obj.memorability      = Math.min(10, Math.max(0, Math.round(obj.memorability ?? obj.brandPotential)));
    obj.useCases          = (obj.useCases as Array<{ title: string; desc: string }>).slice(0, 3).map(u => ({
      title: String(u.title ?? "").slice(0, 30),
      desc:  String(u.desc  ?? "").slice(0, 80),
    }));
    obj.summary = String(obj.summary).slice(0, 300);

    const verdictMap: Record<string, string> = {
      "强烈推荐": "#dc2626",
      "值得关注": "#d97706",
      "一般":    "#64748b",
      "不推荐":  "#94a3b8",
    };
    if (!verdictMap[obj.investmentVerdict]) obj.investmentVerdict = "一般";
    obj.verdictColor = verdictMap[obj.investmentVerdict];

    return obj as Omit<DomainAiAnalysis, "domain" | "model" | "cached" | "analyzedAt">;
  } catch {
    return null;
  }
}

export async function analyzeDomainWithAi(domain: string): Promise<DomainAiAnalysis | null> {
  const redisClient = isRedisAvailable() ? redis : null;

  // Try cache first
  if (redisClient) {
    try {
      const cached = await redisClient.get(cacheKey(domain));
      if (cached) {
        const parsed = JSON.parse(cached) as DomainAiAnalysis;
        parsed.cached = true;
        return parsed;
      }
    } catch { /* ignore cache errors */ }
  }

  // Get available AI providers
  const providers = getConfiguredProviders();
  if (providers.length === 0) return null;

  const messages = [
    { role: "user" as const, content: buildPrompt(domain) },
  ];

  let lastError: Error | null = null;
  for (const provider of providers.slice(0, 3)) {  // try up to 3 providers
    try {
      const raw = await provider.chat(messages);
      const parsed = parseAiResponse(raw);
      if (!parsed) {
        lastError = new Error(`${provider.name}: invalid JSON response`);
        continue;
      }

      const result: DomainAiAnalysis = {
        domain,
        ...parsed,
        model: provider.name,
        cached: false,
        analyzedAt: new Date().toISOString(),
      };

      // Cache the result
      if (redisClient) {
        try {
          await redisClient.set(cacheKey(domain), JSON.stringify(result), "EX", CACHE_TTL);
        } catch { /* ignore */ }
      }

      return result;
    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
      continue;
    }
  }

  logger.error("[domain-value-ai] All providers failed:", lastError?.message);
  return null;
}
