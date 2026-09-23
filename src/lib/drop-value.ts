/**
 * Extended, multi-dimension domain value scoring for drop-calendar leads.
 *
 * Dimensions (max 100):
 *   Length   (0-25) — rarity of short names
 *   TLD      (0-15) — premium TLDs
 *   Lexical  (0-20) — English dictionary words, Chinese shuangpin, category keywords
 *   Trending (0-15) — matches the hot_prefixes watchlist
 *   Pattern  (0-15) — numeric luck, pronounceability, palindromes, repeats
 *   Market   (0-10) — backlink count (BL) and domain popularity (DP)
 *
 * `scoreDomain` in domain-value.ts stays untouched for existing callers.
 */

import { ENGLISH_WORDS } from "@/data/wordlist";
import { PINYIN_SYLLABLES, PINYIN_WORDS } from "@/data/pinyin";
import {
  ALERT_KEYWORDS,
  TLD_SCORES,
  AI_TECH_WORDS,
  WEB3_CRYPTO_WORDS,
  FINANCE_WORDS,
  SAAS_WORDS,
  CLOUD_INFRA_WORDS,
  CONSUMER_BRAND_WORDS,
  pronounceabilityScore,
  chineseNumberBonus,
  extractSubwords,
  type DomainValueResult,
} from "@/lib/domain-value";

export interface ValueContext {
  hotPrefixes: Map<string, number>;
  wordSet?: ReadonlySet<string>;
  pinyinSyllables?: ReadonlySet<string>;
  pinyinWords?: ReadonlySet<string>;
  bl?: number | null;
  dp?: number | null;
}

export interface ExtendedValueBreakdown {
  lengthScore: number;
  tldScore: number;
  lexicalScore: number;
  trendingScore: number;
  patternScore: number;
  marketScore: number;
}

export interface ExtendedValueResult {
  score: number;
  tier: DomainValueResult["tier"];
  tierColor: string;
  tierEn: DomainValueResult["tierEn"];
  isAlertKeyword: boolean;
  isNumericOnly: boolean;
  isSingleChar: boolean;
  isDictionaryWord: boolean;
  isPinyin: boolean;
  reasons: string[];
  breakdown: ExtendedValueBreakdown;
}

export interface ValueThresholds {
  top: number;
  high: number;
  medium: number;
  normal: number;
}

export const DEFAULT_VALUE_THRESHOLDS: ValueThresholds = {
  top: 78,
  high: 58,
  medium: 36,
  normal: 16,
};

/** Whether the SLD is a complete English dictionary word. */
export function isDictionaryWord(sld: string, words: ReadonlySet<string> = ENGLISH_WORDS): boolean {
  return words.has(sld);
}

/**
 * Split a lowercase-letter SLD into valid pinyin syllables.
 * Returns the minimal-syllable split, or null when no complete split exists.
 */
export function splitPinyin(
  sld: string,
  syllables: ReadonlySet<string> = PINYIN_SYLLABLES,
): string[] | null {
  if (!/^[a-z]+$/.test(sld)) return null;
  const n = sld.length;
  if (n < 2 || n > 12) return null;

  const best: (string[] | null)[] = new Array(n + 1).fill(null);
  best[0] = [];
  for (let i = 0; i < n; i++) {
    if (!best[i]) continue;
    for (let len = 1; len <= 6 && i + len <= n; len++) {
      const part = sld.slice(i, i + len);
      if (!syllables.has(part)) continue;
      const candidate = [...best[i]!, part];
      if (!best[i + len] || candidate.length < best[i + len]!.length) {
        best[i + len] = candidate;
      }
    }
  }
  return best[n];
}

interface Dimension {
  score: number;
  reasons: string[];
}

function lengthScoreOf(name: string): Dimension {
  const n = name.length;
  if (n === 1) return { score: 25, reasons: ["单字符·极稀缺"] };
  if (n === 2) return { score: 23, reasons: ["双字符·顶级短域"] };
  if (n === 3) return { score: 19, reasons: ["三字符·优质短域"] };
  if (n === 4) return { score: 14, reasons: ["四字符短域名"] };
  if (n === 5) return { score: 9, reasons: [] };
  if (n === 6) return { score: 5, reasons: [] };
  if (n <= 8) return { score: 2, reasons: [] };
  return { score: 0, reasons: [] };
}

function tldScoreOf(effectiveTld: string, tld: string): Dimension {
  const raw = TLD_SCORES[effectiveTld] ?? TLD_SCORES[tld] ?? 2;
  const score = Math.round((raw / 20) * 15);
  const reasons: string[] = [];
  if (score >= 13) reasons.push(`顶级后缀 .${effectiveTld}`);
  else if (score >= 10) reasons.push(`优质后缀 .${effectiveTld}`);
  return { score, reasons };
}

function lexicalScoreOf(
  name: string,
  words: ReadonlySet<string>,
  syllables: ReadonlySet<string>,
  pinyinWords: ReadonlySet<string>,
): Dimension & { isWord: boolean; isPinyin: boolean } {
  const reasons: string[] = [];
  let wordScore = 0;
  let pinyinScore = 0;
  let categoryScore = 0;
  let isWord = false;
  let isPinyin = false;

  if (words.has(name)) {
    isWord = true;
    const n = name.length;
    if (n <= 3) wordScore = 20;
    else if (n === 4) wordScore = 18;
    else if (n === 5) wordScore = 15;
    else if (n === 6) wordScore = 12;
    else if (n <= 8) wordScore = 9;
    else wordScore = 6;
    reasons.push(`英文单词·${n} 字母`);
  }

  const parts = splitPinyin(name, syllables);
  if (parts) {
    isPinyin = true;
    if (pinyinWords.has(name)) { pinyinScore = 18; reasons.push("常用双拼词"); }
    else if (parts.length === 2) { pinyinScore = 14; reasons.push("双拼·可读拼音"); }
    else if (parts.length === 3) { pinyinScore = 10; reasons.push("三拼音节"); }
    else { pinyinScore = 7; reasons.push("拼音音节组合"); }
  }

  const sub3 = name.length > 3 ? extractSubwords(name, 3) : [name];
  const subAll = name.length > 3 ? extractSubwords(name, 2) : [name];
  if ([name, ...sub3].some(w => AI_TECH_WORDS.has(w))) { categoryScore = 20; reasons.push("AI/大模型热词"); }
  else if ([name, ...sub3].some(w => WEB3_CRYPTO_WORDS.has(w))) { categoryScore = 17; reasons.push("Web3/加密热词"); }
  else if ([name, ...sub3].some(w => FINANCE_WORDS.has(w))) { categoryScore = 16; reasons.push("金融/支付热词"); }
  else if ([name, ...sub3].some(w => SAAS_WORDS.has(w))) { categoryScore = 14; reasons.push("SaaS/企服热词"); }
  else if ([name, ...subAll].some(w => CLOUD_INFRA_WORDS.has(w))) { categoryScore = 11; reasons.push("云计算/基础设施词"); }
  else if ([name, ...subAll].some(w => CONSUMER_BRAND_WORDS.has(w))) { categoryScore = 9; reasons.push("消费品牌词"); }

  return {
    score: Math.min(20, Math.max(wordScore, pinyinScore, categoryScore)),
    reasons,
    isWord,
    isPinyin,
  };
}

function trendingScoreOf(name: string, hotPrefixes: Map<string, number>): Dimension {
  let best = 0;
  let bestPrefix = "";
  for (const [prefix, weight] of hotPrefixes) {
    if (!prefix || !weight || weight <= 0) continue;
    if (name === prefix || name.startsWith(prefix)) {
      if (weight > best) { best = weight; bestPrefix = prefix; }
    } else if (prefix.length >= 3 && name.includes(prefix)) {
      const discounted = weight * 0.6;
      if (discounted > best) { best = discounted; bestPrefix = prefix; }
    }
  }
  const score = Math.min(15, Math.round((best / 30) * 15));
  return { score, reasons: score > 0 ? [`热门前缀 ${bestPrefix}`] : [] };
}

function patternScoreOf(name: string): Dimension {
  const reasons: string[] = [];
  let raw = 0;

  if (/^\d+$/.test(name)) {
    const chBonus = chineseNumberBonus(name);
    raw += 8 + chBonus;
    reasons.push(chBonus >= 5 ? `纯数字·吉祥数 ${name}` : "纯数字域名");
  } else if (/^[a-z]+$/.test(name)) {
    const pron = pronounceabilityScore(name);
    if (pron >= 5) {
      raw += pron;
      reasons.push(name.length <= 4 ? "短域·易读易记" : "发音优美·可读性强");
    } else {
      raw += Math.min(pron + 1, 4);
    }
  }

  if (!/[-_]/.test(name)) raw += 2;
  if (name.length >= 2 && name === [...name].reverse().join("")) {
    raw += 3;
    reasons.push("回文域名");
  }
  if (/^(.)\1+$/.test(name) && name.length >= 2) {
    raw += 3;
    reasons.push("重复字符型");
  }

  return { score: Math.min(15, Math.round((raw / 20) * 15)), reasons };
}

function normalizeLog(value: number, max: number): number {
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.min(1, Math.log10(value + 1) / Math.log10(max + 1));
}

function marketScoreOf(bl: number | null | undefined, dp: number | null | undefined): Dimension {
  const blVal = Number(bl) || 0;
  const dpVal = Number(dp) || 0;
  const blScore = normalizeLog(blVal, 1_000_000) * 10;
  const dpScore = normalizeLog(dpVal, 10_000) * 10;
  const score = Math.round(Math.max(blScore, dpScore));
  const reasons: string[] = [];
  if (blScore >= 5) reasons.push(`外链丰富 BL=${Math.round(blVal)}`);
  else if (dpScore >= 5) reasons.push("高流行度域名");
  return { score, reasons };
}

function tierOf(score: number, t: ValueThresholds): Pick<ExtendedValueResult, "tier" | "tierEn" | "tierColor"> {
  if (score >= t.top) return { tier: "极高", tierEn: "top", tierColor: "#dc2626" };
  if (score >= t.high) return { tier: "高", tierEn: "high", tierColor: "#d97706" };
  if (score >= t.medium) return { tier: "中高", tierEn: "medium", tierColor: "#7c3aed" };
  if (score >= t.normal) return { tier: "普通", tierEn: "normal", tierColor: "#64748b" };
  return { tier: "低", tierEn: "low", tierColor: "#94a3b8" };
}

/**
 * Score a domain across all dimensions. Returns null for non-domain input.
 * Deterministic for a given domain + context.
 */
export function scoreDomainExtended(
  domain: string,
  context: ValueContext,
  thresholds: ValueThresholds = DEFAULT_VALUE_THRESHOLDS,
): ExtendedValueResult | null {
  const lower = String(domain ?? "").toLowerCase().trim();
  const dotIdx = lower.lastIndexOf(".");
  if (dotIdx < 1) return null;

  const sld = lower.slice(0, dotIdx);
  const tld = lower.slice(dotIdx + 1);
  const secondDot = sld.lastIndexOf(".");
  const actualName = secondDot >= 0 ? sld.slice(0, secondDot) : sld;
  const effectiveTld = secondDot >= 0 ? `${sld.slice(secondDot + 1)}.${tld}` : tld;
  if (!actualName) return null;

  const words = context.wordSet ?? ENGLISH_WORDS;
  const syllables = context.pinyinSyllables ?? PINYIN_SYLLABLES;
  const pinyinWords = context.pinyinWords ?? PINYIN_WORDS;

  const isNumericOnly = /^\d+$/.test(actualName);
  const isSingleChar = actualName.length === 1;
  const isAlertKeyword = ALERT_KEYWORDS.has(actualName) || isSingleChar || isNumericOnly;

  const length = lengthScoreOf(actualName);
  const tldDim = tldScoreOf(effectiveTld, tld);
  const lexical = lexicalScoreOf(actualName, words, syllables, pinyinWords);
  const trending = trendingScoreOf(actualName, context.hotPrefixes);
  const pattern = patternScoreOf(actualName);
  const market = marketScoreOf(context.bl, context.dp);

  const breakdown: ExtendedValueBreakdown = {
    lengthScore: length.score,
    tldScore: tldDim.score,
    lexicalScore: lexical.score,
    trendingScore: trending.score,
    patternScore: pattern.score,
    marketScore: market.score,
  };

  const raw = Object.values(breakdown).reduce((sum, v) => sum + v, 0);
  const score = Math.min(100, raw);

  const reasons = [
    ...length.reasons,
    ...tldDim.reasons,
    ...lexical.reasons,
    ...trending.reasons,
    ...pattern.reasons,
    ...market.reasons,
  ];

  return {
    score,
    ...tierOf(score, thresholds),
    isAlertKeyword,
    isNumericOnly,
    isSingleChar,
    isDictionaryWord: lexical.isWord,
    isPinyin: lexical.isPinyin,
    reasons: reasons.slice(0, 5),
    breakdown,
  };
}

/** Whether a scored lead should trigger an admin alert. */
export function shouldAlertExtended(result: ExtendedValueResult): boolean {
  return result.isAlertKeyword || result.score >= 68;
}

/**
 * Build the hot-prefix weight map consumed by {@link scoreDomainExtended}.
 * Accepts rows from `hot_prefixes` (enabled only) or the seeded prefix list.
 */
export function buildHotPrefixMap(
  prefixes: ReadonlyArray<{ prefix: string; weight: number }>,
): Map<string, number> {
  const map = new Map<string, number>();
  for (const row of prefixes) {
    const key = String(row?.prefix ?? "").toLowerCase().trim();
    const weight = Number(row?.weight);
    if (!key || !Number.isFinite(weight) || weight <= 0) continue;
    const existing = map.get(key) ?? 0;
    if (weight > existing) map.set(key, weight);
  }
  return map;
}
