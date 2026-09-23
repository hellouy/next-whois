/**
 * Multi-dimensional domain value scoring system.
 * Returns a score 0-100 and a breakdown of scoring factors.
 *
 * Scoring dimensions:
 *   Length     (0-30) — shorter is rarer and more valuable
 *   TLD        (0-20) — premium TLDs score higher
 *   Keyword    (0-30) — hot market segments, brand terms
 *   Pattern    (0-20) — numeric, letter patterns, pronounceability
 */

// ── Alert keywords (always notify admin when available) ──────────────────────
export const ALERT_KEYWORDS = new Set([
  // Infrastructure / meta
  "www", "domain", "domains", "whois", "rdap", "dns", "nic", "iana",
  // Protocol / network
  "api", "ssl", "tls", "cert", "cdn", "proxy", "vpn", "server", "host",
  "hosting", "ip", "ipv4", "ipv6", "asn", "cidr", "smtp", "http", "ftp",
  // Common TLD words queried as SLD
  "com", "net", "org", "io", "co", "app", "dev", "ai",
  // Registrar / registry
  "register", "registrar", "registry", "nameserver", "ns",
  "transfer", "renew", "renewal", "expire",
  // AI / LLM models & companies
  "gpt", "llm", "agi", "grok", "claude", "gemini", "openai", "deepseek",
  "chatgpt", "sora", "dalle", "midjourney", "copilot", "cursor", "perplexity",
  "manus", "anthropic", "mistral", "cohere", "stability", "runway",
  // Mega brands
  "google", "apple", "microsoft", "amazon", "meta", "tesla", "nvidia",
  "alibaba", "tencent", "baidu", "bytedance", "huawei",
]);

// ── Keyword categories (for scoring) ─────────────────────────────────────────

/** AI / LLM / ML ecosystem — hottest segment */
export const AI_TECH_WORDS = new Set([
  // Core AI terms
  "ai", "gpt", "llm", "llms", "ml", "agi", "agi", "slm", "vlm", "nlp",
  "rag", "bot", "agi", "grok", "claude", "gemini", "openai", "sora", "dalle",
  "copilot", "deepseek", "chatgpt", "mistral", "llama", "diffusion",
  "neural", "vision", "model", "inference", "embedding", "embedding",
  "vector", "finetune", "finetuning", "pretrain", "lora", "rlhf",
  "transformer", "attention", "encoder", "decoder", "multimodal",
  // AI companies & products
  "anthropic", "cohere", "stability", "runway", "pika", "heygen",
  "synthesia", "suno", "elevenlabs", "whisper", "sam", "flux", "comfy",
  "perplexity", "cursor", "manus", "devin", "codex", "copilot",
  // AI workflow / infra
  "agent", "agents", "agentic", "autopilot", "automate", "workflow",
  "swarm", "orch", "pipeline", "langchain", "llamaindex", "crewai",
  "autogen", "dspy", "promptflow", "semantic", "retrieval",
  // Compute / infra
  "gpu", "tpu", "cuda", "vllm", "triton", "onnx", "tensorrt",
  "mlflow", "wandb", "kubeflow", "vertex", "sagemaker", "bedrock",
]);

/** Web3 / Crypto / DeFi ecosystem */
export const WEB3_CRYPTO_WORDS = new Set([
  // Core concepts
  "crypto", "web3", "defi", "nft", "dao", "dex", "dapp", "cefi",
  "wallet", "coin", "token", "chain", "layer", "rollup", "evm", "erc",
  "zk", "zkp", "stark", "groth", "snark", "proof", "zkvm",
  // Chains / L2s
  "eth", "btc", "sol", "sui", "aptos", "cosmos", "juno", "osmo",
  "matic", "polygon", "arb", "arbitrum", "op", "optimism", "base",
  "mantle", "scroll", "zksync", "linea", "starknet", "mina",
  "celestia", "eigen", "restake", "avs", "modular",
  // DeFi protocols
  "aave", "compound", "maker", "lido", "rocket", "frax", "curve",
  "balancer", "uniswap", "sushi", "gmx", "dydx", "perp", "hyperliquid",
  "1inch", "cowswap", "paraswap", "yield", "staking", "stake",
  "airdrop", "mint", "bridge", "swap", "pool", "vault", "borrow",
  // Infra / tools
  "rpc", "node", "validator", "relay", "indexer", "subgraph", "oracle",
  "chainlink", "pyth", "band", "uma", "api3", "tellor",
  // Culture
  "hodl", "gm", "wagmi", "ngmi", "wen", "fren", "vibes", "degen",
]);

/** Finance / Payments / Fintech */
export const FINANCE_WORDS = new Set([
  "pay", "payment", "payments", "bank", "banking", "finance", "fintech",
  "invest", "fund", "asset", "wealth", "money", "cash", "forex",
  "stock", "trade", "trading", "market", "exchange", "brokerage",
  "insurance", "loan", "credit", "debt", "mortgage", "ledger",
  "accounting", "audit", "tax", "payroll", "invoice", "billing",
  "transfer", "remit", "swift", "ach", "sepa", "iban", "usdc", "usdt",
]);

/** SaaS / B2B / Enterprise Software */
export const SAAS_WORDS = new Set([
  "saas", "paas", "iaas", "caas", "xaas", "crm", "erp", "hrm",
  "oms", "wms", "cms", "lms", "rms", "pms", "bpm", "rpa",
  "ecommerce", "commerce", "cart", "checkout", "fulfillment",
  "analytics", "dashboard", "insight", "report", "bi", "etl",
  "integration", "connector", "webhook", "zapier", "make", "n8n",
  "automation", "orchestration", "scheduling", "notification",
  "onboard", "offboard", "provision", "identity", "sso", "oauth",
  "saml", "scim", "rbac", "iam", "keystore", "secret", "vault",
]);

/** Cloud / Infrastructure / DevOps */
export const CLOUD_INFRA_WORDS = new Set([
  "cloud", "infra", "infrastructure", "devops", "devsecops",
  "k8s", "kubernetes", "docker", "container", "helm", "istio",
  "terraform", "pulumi", "ansible", "chef", "puppet", "salt",
  "ci", "cd", "cicd", "pipeline", "deploy", "deployment", "release",
  "monitoring", "observability", "tracing", "logging", "alerting",
  "prometheus", "grafana", "datadog", "newrelic", "sentry", "pagerduty",
  "cdn", "edge", "mesh", "gateway", "proxy", "loadbalancer", "nginx",
  "kafka", "rabbitmq", "redis", "postgres", "mongo", "elastic",
  "s3", "blob", "bucket", "storage", "backup", "snapshot", "repo",
  "data", "code", "dev", "tech", "hub", "lab", "stack", "base",
  "core", "node", "grid", "platform", "engine", "service", "system",
  "tools", "kit", "open", "free", "auto", "meta", "micro", "nano",
  "scale", "stream", "pipe", "wire", "link", "connect", "bridge", "gate",
  "search", "index", "cache", "log", "trace", "monitor", "alert",
  "build", "test", "lint", "debug", "profile", "benchmark", "load",
]);

/** Consumer / Brand / Commerce */
export const CONSUMER_BRAND_WORDS = new Set([
  "shop", "store", "mall", "mart", "market", "buy", "sell", "deal",
  "startup", "venture", "global", "world", "inter", "pro", "plus",
  "max", "ultra", "prime", "top", "best", "first", "one", "now",
  "go", "get", "my", "me", "new", "next", "super", "hyper", "mega",
  "smart", "fast", "quick", "instant", "live", "real", "true",
  "easy", "simple", "clean", "clear", "bright", "fresh", "bold",
  "rich", "elite", "select", "choice", "pick", "find", "seek",
  "hire", "work", "team", "collab", "share", "social", "community",
  "media", "news", "blog", "post", "feed", "content", "creator",
  "learn", "edu", "course", "skill", "coach", "mentor", "tutor",
  "health", "care", "med", "clinic", "therapy", "wellness", "fit",
  "food", "eat", "meal", "recipe", "cook", "chef", "kitchen",
  "travel", "trip", "tour", "hotel", "stay", "book", "flight",
  "game", "play", "fun", "sport", "bet", "win",
  "art", "design", "creative", "studio", "photo", "video", "music",
]);

// ── TLD value scores (0-20) ───────────────────────────────────────────────────
export const TLD_SCORES: Record<string, number> = {
  com: 20, ai: 19, io: 16, net: 14, org: 13,
  co: 13, app: 12, dev: 11, me: 10, gg: 10,
  so: 9, to: 9, ly: 8, sh: 8,
  cn: 9, "com.cn": 9, hk: 8, sg: 7, tw: 7, jp: 6, kr: 6,
  uk: 7, "co.uk": 7, de: 6, fr: 5, nl: 5, ca: 5, au: 5,
  info: 5, biz: 4, xyz: 4, online: 3, site: 3, web: 3,
  tech: 5, cloud: 4, pro: 5, agency: 3, studio: 4,
  finance: 4, money: 3, capital: 4, fund: 3,
  health: 3, care: 3, medical: 3,
  games: 3, bet: 3,
};

// ── Consonants and vowels for pronounceability ────────────────────────────────
const VOWELS = new Set(["a", "e", "i", "o", "u"]);
function isVowel(c: string) { return VOWELS.has(c); }
function isConsonant(c: string) { return /[a-z]/.test(c) && !VOWELS.has(c); }

/** CVCV / VCVC / CVVC pattern — pronounceable, more brandable */
export function pronounceabilityScore(name: string): number {
  if (!/^[a-z]+$/.test(name)) return 0;
  const len = name.length;
  if (len < 2 || len > 8) return 0;
  let score = 0;
  // Count alternating vowel-consonant patterns
  let alternating = 0;
  for (let i = 0; i < len - 1; i++) {
    const a = name[i], b = name[i + 1];
    if ((isVowel(a) && isConsonant(b)) || (isConsonant(a) && isVowel(b))) alternating++;
  }
  const ratio = alternating / (len - 1);
  if (ratio >= 0.8) score = len <= 4 ? 6 : len <= 6 ? 4 : 2;
  else if (ratio >= 0.6) score = len <= 4 ? 3 : 2;
  return score;
}

/** Chinese market: numbers 8, 6, 9 are lucky (higher value) */
export function chineseNumberBonus(name: string): number {
  if (!/^\d+$/.test(name)) return 0;
  let score = 0;
  const lucky = name.split("").filter(c => c === "8" || c === "6" || c === "9").length;
  const unlucky = name.split("").filter(c => c === "4").length;
  score += lucky * 2;
  score -= unlucky * 1;
  if (/^8+$/.test(name)) score += 5;     // all-8s: super lucky
  if (/^6+$/.test(name)) score += 4;
  if (name.includes("88")) score += 3;
  if (name.includes("66")) score += 2;
  if (name.includes("168")) score += 3;  // yì lù fā (一路发)
  if (name.includes("666")) score += 4;
  if (name.includes("888")) score += 5;
  if (name.includes("8888")) score += 7;
  return Math.max(0, Math.min(score, 12));
}

export type DomainValueResult = {
  score: number;
  tier: "极高" | "高" | "中高" | "普通" | "低";
  tierColor: string;
  tierEn: "top" | "high" | "medium" | "normal" | "low";
  isAlertKeyword: boolean;
  isNumericOnly: boolean;
  isSingleChar: boolean;
  isPronounceablePremium: boolean;
  reasons: string[];
  breakdown: {
    lengthScore: number;
    tldScore: number;
    keywordScore: number;
    patternScore: number;
  };
};

export function scoreDomain(query: string, queryType: string): DomainValueResult | null {
  if (queryType !== "domain") return null;

  const lower = query.toLowerCase();
  const dotIdx = lower.lastIndexOf(".");
  if (dotIdx < 1) return null;

  const sld = lower.slice(0, dotIdx);
  const tld = lower.slice(dotIdx + 1);

  // Handle multi-part TLDs like com.cn
  const secondDot = sld.lastIndexOf(".");
  const actualName = secondDot >= 0 ? sld.slice(0, secondDot) : sld;
  const effectiveTld = secondDot >= 0 ? `${sld.slice(secondDot + 1)}.${tld}` : tld;

  const nameLen = actualName.length;
  const isNumericOnly = /^\d+$/.test(actualName);
  const isSingleChar = nameLen === 1;
  const isAlertKeyword = ALERT_KEYWORDS.has(actualName) || isSingleChar || isNumericOnly;

  const reasons: string[] = [];
  let lengthScore = 0;
  let tldScore = 0;
  let keywordScore = 0;
  let patternScore = 0;

  // ── 1. Length score (0-30) ─────────────────────────────────────────────────
  if (nameLen === 1)       { lengthScore = 30; reasons.push("单字符·极稀缺"); }
  else if (nameLen === 2)  { lengthScore = 28; reasons.push("双字符·顶级短域"); }
  else if (nameLen === 3)  { lengthScore = 24; reasons.push("三字符·优质短域"); }
  else if (nameLen === 4)  { lengthScore = 18; reasons.push("四字符短域名"); }
  else if (nameLen === 5)  { lengthScore = 12; }
  else if (nameLen === 6)  { lengthScore = 7; }
  else if (nameLen <= 8)   { lengthScore = 3; }
  else                     { lengthScore = 0; }

  // ── 2. TLD score (0-20) ────────────────────────────────────────────────────
  tldScore = TLD_SCORES[effectiveTld] ?? TLD_SCORES[tld] ?? 2;
  if (tldScore >= 18) reasons.push(`顶级后缀 .${effectiveTld}`);
  else if (tldScore >= 13) reasons.push(`优质后缀 .${effectiveTld}`);
  else if (tldScore >= 9) reasons.push(`优质地区后缀 .${effectiveTld}`);

  // ── 3. Keyword score (0-30) ────────────────────────────────────────────────
  // For premium categories (AI, Web3) only match subwords ≥ 3 chars to avoid
  // false positives like "op" (Optimism) matching inside "shop".
  const subwords3 = actualName.length > 3 ? extractSubwords(actualName, 3) : [actualName];
  const subwordsAll = actualName.length > 3 ? extractSubwords(actualName, 2) : [actualName];

  // Score by category (highest wins, alert keyword bonus on top)
  const inAI    = [actualName, ...subwords3].some(w => AI_TECH_WORDS.has(w));
  const inWeb3  = [actualName, ...subwords3].some(w => WEB3_CRYPTO_WORDS.has(w));
  const inFin   = [actualName, ...subwords3].some(w => FINANCE_WORDS.has(w));
  const inSaaS  = [actualName, ...subwords3].some(w => SAAS_WORDS.has(w));
  const inCloud = [actualName, ...subwordsAll].some(w => CLOUD_INFRA_WORDS.has(w));
  const inBrand = [actualName, ...subwordsAll].some(w => CONSUMER_BRAND_WORDS.has(w));
  const inAlert = ALERT_KEYWORDS.has(actualName);

  if (inAI)    { keywordScore = Math.max(keywordScore, 28); reasons.push("AI/大模型热词"); }
  if (inWeb3)  { keywordScore = Math.max(keywordScore, 24); reasons.push("Web3/加密热词"); }
  if (inFin)   { keywordScore = Math.max(keywordScore, 22); reasons.push("金融/支付热词"); }
  if (inSaaS)  { keywordScore = Math.max(keywordScore, 20); reasons.push("SaaS/企服热词"); }
  if (inCloud) { keywordScore = Math.max(keywordScore, 16); reasons.push("云计算/基础设施词"); }
  if (inBrand) { keywordScore = Math.max(keywordScore, 13); reasons.push("消费品牌词"); }
  if (inAlert) { keywordScore = Math.max(keywordScore, 25); reasons.push("特殊关键词"); }

  // ── 4. Pattern score (0-20) ────────────────────────────────────────────────
  if (isNumericOnly) {
    // Numeric domain patterns
    const chBonus = chineseNumberBonus(actualName);
    patternScore += 8 + chBonus;
    if (chBonus >= 5)  reasons.push(`纯数字·吉祥数 ${actualName}`);
    else               reasons.push(`纯数字域名（${nameLen}位）`);
  } else if (isSingleChar) {
    patternScore += 8;
  } else if (/^[a-z]+$/.test(actualName)) {
    // Letter-only: check pronounceability
    const pronScore = pronounceabilityScore(actualName);
    if (pronScore >= 5) {
      patternScore += pronScore;
      if (nameLen <= 4) reasons.push("短域·易读易记");
      else reasons.push("发音优美·可读性强");
    } else {
      patternScore += Math.min(pronScore + 1, 4);
      if (nameLen <= 6) reasons.push("纯字母无连字符");
    }
  }

  // No hyphen / underscore bonus
  if (!/[-_]/.test(actualName)) patternScore += 2;

  // Palindrome bonus
  if (nameLen >= 2 && actualName === [...actualName].reverse().join("")) {
    patternScore += 3;
    reasons.push("回文域名");
  }

  // Repeating character pattern (aa, bbb, abab)
  if (/^(.)\1+$/.test(actualName) && nameLen >= 2) {
    patternScore += 3;
    reasons.push("重复字符型");
  }
  if (/^(..)\1+$/.test(actualName) && nameLen >= 4) {
    patternScore += 2;
  }

  // Cap pattern score
  patternScore = Math.min(patternScore, 20);

  // ── Final score ────────────────────────────────────────────────────────────
  const raw = lengthScore + tldScore + keywordScore + patternScore;
  const score = Math.min(100, raw);

  let tier: DomainValueResult["tier"];
  let tierEn: DomainValueResult["tierEn"];
  let tierColor: string;
  if (score >= 78) { tier = "极高"; tierEn = "top";    tierColor = "#dc2626"; }
  else if (score >= 58) { tier = "高";   tierEn = "high";   tierColor = "#d97706"; }
  else if (score >= 36) { tier = "中高"; tierEn = "medium"; tierColor = "#7c3aed"; }
  else if (score >= 16) { tier = "普通"; tierEn = "normal"; tierColor = "#64748b"; }
  else                  { tier = "低";   tierEn = "low";    tierColor = "#94a3b8"; }

  const isPronounceablePremium = /^[a-z]+$/.test(actualName) && pronounceabilityScore(actualName) >= 5 && nameLen <= 6;

  return {
    score,
    tier,
    tierColor,
    tierEn,
    isAlertKeyword,
    isNumericOnly,
    isSingleChar,
    isPronounceablePremium,
    reasons: reasons.slice(0, 4),
    breakdown: { lengthScore, tldScore, keywordScore, patternScore },
  };
}

/** Extract candidate sub-words from a domain name (minLen: minimum subword length) */
export function extractSubwords(name: string, minLen = 2): string[] {
  const words: string[] = [];
  const maxLen = Math.min(name.length, 12);
  for (let len = minLen; len <= maxLen; len++) {
    for (let start = 0; start <= name.length - len; start++) {
      words.push(name.slice(start, start + len));
    }
  }
  return words;
}

/** Determine if this domain should trigger an admin alert email. */
export function shouldAlertAdmin(
  query: string,
  queryType: string,
  regStatus: string,
): boolean {
  if (regStatus !== "unregistered") return false;
  if (queryType !== "domain") return false;
  const result = scoreDomain(query, queryType);
  if (!result) return false;
  return result.isAlertKeyword || result.score >= 68;
}
