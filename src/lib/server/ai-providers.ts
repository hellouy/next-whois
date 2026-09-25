/**
 * Multi-model AI provider system for TLD lifecycle extraction.
 * Models are tried in priority order; fallback to next on failure.
 *
 * Keys can come from two sources (DB takes priority over env var):
 *   DB (site_settings table) via api_ai_*_key keys — set in Admin → API 接入
 *   Env vars: ZHIPU_API_KEY, GROQ_API_KEY, GEMINI_API_KEY, DEEPSEEK_API_KEY,
 *             DASHSCOPE_API_KEY, MOONSHOT_API_KEY, SILICONFLOW_API_KEY,
 *             QIANFAN_API_KEY
 *
 * Free providers supported:
 *   ZHIPU_API_KEY     → GLM-4-FlashX, GLM-4-Flash, GLM-4-Air  (bigmodel.cn, free quota)
 *   GROQ_API_KEY      → Llama-3.3-70B, Mixtral-8x7B             (groq.com, free tier)
 *   GEMINI_API_KEY    → Gemini-2.0-Flash, Gemini-1.5-Flash       (ai.google.dev, free tier)
 *   DEEPSEEK_API_KEY  → DeepSeek-V3, DeepSeek-V2.5               (platform.deepseek.com, free)
 *   DASHSCOPE_API_KEY → Qwen-Turbo, Qwen-Long                    (dashscope.aliyun.com, free)
 *   MOONSHOT_API_KEY  → Kimi moonshot-v1-8k                      (platform.moonshot.cn, free)
 *   SILICONFLOW_API_KEY → Qwen2.5-7B, Llama-3.1-8B etc.         (siliconflow.cn, free)
 *   QIANFAN_API_KEY   → ERNIE-Speed-8K, ERNIE-Lite-8K            (qianfan.baidu.com, free)
 */

export interface AiProviderInfo {
  id: string;
  name: string;
  model: string;
  provider: string;
  env_var: string;
  db_key: string;
  configured: boolean;
  priority: number;
  source?: "env" | "db";
}

type ChatRole = "system" | "user";

export interface AiProvider extends AiProviderInfo {
  chat: (messages: { role: ChatRole; content: string }[]) => Promise<string>;
}

// ─── DB key mapping: env var name → site_settings key ─────────────────────────
export const AI_DB_KEY_MAP: Record<string, string> = {
  ZHIPU_API_KEY:       "api_ai_zhipu_key",
  GROQ_API_KEY:        "api_ai_groq_key",
  GEMINI_API_KEY:      "api_ai_gemini_key",
  DEEPSEEK_API_KEY:    "api_ai_deepseek_key",
  DASHSCOPE_API_KEY:   "api_ai_dashscope_key",
  MOONSHOT_API_KEY:    "api_ai_moonshot_key",
  SILICONFLOW_API_KEY: "api_ai_siliconflow_key",
  QIANFAN_API_KEY:     "api_ai_qianfan_key",
};

// ─── In-process DB key cache (5 min TTL) ─────────────────────────────────────
let _dbKeyCache: Record<string, string> = {};
let _dbKeyCacheTs = 0;
const DB_KEY_CACHE_TTL = 5 * 60 * 1000;

export function invalidateProviders(): void {
  _dbKeyCache = {};
  _dbKeyCacheTs = 0;
}

async function loadDbKeys(): Promise<Record<string, string>> {
  const now = Date.now();
  if (now - _dbKeyCacheTs < DB_KEY_CACHE_TTL) return _dbKeyCache;
  try {
    const { many } = await import("@/lib/db-query");
    const dbKeyNames = Object.values(AI_DB_KEY_MAP);
    const rows = await many<{ key: string; value: string }>(
      `SELECT key, value FROM site_settings WHERE key = ANY($1) AND value <> ''`,
      [dbKeyNames],
    );
    const map: Record<string, string> = {};
    for (const row of rows) {
      const envVar = Object.entries(AI_DB_KEY_MAP).find(([, v]) => v === row.key)?.[0];
      if (envVar && row.value) map[envVar] = row.value;
    }
    _dbKeyCache = map;
    _dbKeyCacheTs = now;
    return map;
  } catch {
    return _dbKeyCache;
  }
}

// ─── Helper: OpenAI-compatible POST ──────────────────────────────────────────
async function openAiCompatChat(
  endpoint: string,
  apiKey: string,
  model: string,
  messages: { role: ChatRole; content: string }[]
): Promise<string> {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.1,
      max_tokens: 800,
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    const err = await res.text().catch(() => "");
    throw new Error(`${model} API error ${res.status}: ${err.slice(0, 200)}`);
  }
  const json = await res.json();
  const content: string = json?.choices?.[0]?.message?.content?.trim() ?? "";
  if (!content) throw new Error(`${model} returned empty response`);
  return content;
}

// ─── Helper: Google Gemini ────────────────────────────────────────────────────
async function geminiChat(
  apiKey: string,
  model: string,
  messages: { role: ChatRole; content: string }[]
): Promise<string> {
  const systemMsg = messages.find(m => m.role === "system");
  const userMsgs = messages.filter(m => m.role === "user");
  const mergedUser = systemMsg
    ? `${systemMsg.content}\n\n${userMsgs.map(m => m.content).join("\n")}`
    : userMsgs.map(m => m.content).join("\n");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: mergedUser }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: 800 },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    const err = await res.text().catch(() => "");
    throw new Error(`Gemini ${model} error ${res.status}: ${err.slice(0, 200)}`);
  }
  const json = await res.json();
  const content: string = json?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? "";
  if (!content) throw new Error(`Gemini returned empty response`);
  return content;
}

// ─── Provider definitions ─────────────────────────────────────────────────────
function buildProviders(dbKeys: Record<string, string> = {}): AiProvider[] {
  const key = (envVar: string): string =>
    dbKeys[envVar] || process.env[envVar] || "";
  const src = (envVar: string): "db" | "env" | undefined =>
    dbKeys[envVar] ? "db" : process.env[envVar] ? "env" : undefined;

  const ZHIPU    = key("ZHIPU_API_KEY");
  const GROQ     = key("GROQ_API_KEY");
  const GEMINI   = key("GEMINI_API_KEY");
  const DEEPSEEK = key("DEEPSEEK_API_KEY");
  const DASH     = key("DASHSCOPE_API_KEY");
  const MOON     = key("MOONSHOT_API_KEY");
  const SILI     = key("SILICONFLOW_API_KEY");
  const QIANFAN  = key("QIANFAN_API_KEY");

  const all: AiProvider[] = [
    // ── Zhipu (primary, existing key) ────────────────────────────────────
    {
      id: "glm4flashx", name: "GLM-4-FlashX", model: "glm-4-flashx",
      provider: "智谱 Zhipu", env_var: "ZHIPU_API_KEY", db_key: AI_DB_KEY_MAP.ZHIPU_API_KEY,
      configured: !!ZHIPU, priority: 10, source: src("ZHIPU_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://open.bigmodel.cn/api/paas/v4/chat/completions", ZHIPU, "glm-4-flashx", msgs),
    },
    {
      id: "glm4flash", name: "GLM-4-Flash", model: "glm-4-flash",
      provider: "智谱 Zhipu", env_var: "ZHIPU_API_KEY", db_key: AI_DB_KEY_MAP.ZHIPU_API_KEY,
      configured: !!ZHIPU, priority: 11, source: src("ZHIPU_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://open.bigmodel.cn/api/paas/v4/chat/completions", ZHIPU, "glm-4-flash", msgs),
    },
    {
      id: "glm4air", name: "GLM-4-Air", model: "glm-4-air",
      provider: "智谱 Zhipu", env_var: "ZHIPU_API_KEY", db_key: AI_DB_KEY_MAP.ZHIPU_API_KEY,
      configured: !!ZHIPU, priority: 20, source: src("ZHIPU_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://open.bigmodel.cn/api/paas/v4/chat/completions", ZHIPU, "glm-4-air", msgs),
    },
    // ── Groq (international, very fast) ──────────────────────────────────
    {
      id: "groq-qwq-32b", name: "QwQ-32B (Groq)", model: "qwen-qwq-32b",
      provider: "Groq", env_var: "GROQ_API_KEY", db_key: AI_DB_KEY_MAP.GROQ_API_KEY,
      configured: !!GROQ, priority: 14, source: src("GROQ_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.groq.com/openai/v1/chat/completions", GROQ, "qwen-qwq-32b", msgs),
    },
    {
      id: "llama33-70b", name: "Llama-3.3-70B (Groq)", model: "llama-3.3-70b-versatile",
      provider: "Groq", env_var: "GROQ_API_KEY", db_key: AI_DB_KEY_MAP.GROQ_API_KEY,
      configured: !!GROQ, priority: 15, source: src("GROQ_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.groq.com/openai/v1/chat/completions", GROQ, "llama-3.3-70b-versatile", msgs),
    },
    {
      id: "groq-mixtral-8x7b", name: "Mixtral-8x7B (Groq)", model: "mixtral-8x7b-32768",
      provider: "Groq", env_var: "GROQ_API_KEY", db_key: AI_DB_KEY_MAP.GROQ_API_KEY,
      configured: !!GROQ, priority: 16, source: src("GROQ_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.groq.com/openai/v1/chat/completions", GROQ, "mixtral-8x7b-32768", msgs),
    },
    {
      id: "gemma2-9b", name: "Gemma2-9B (Groq)", model: "gemma2-9b-it",
      provider: "Groq", env_var: "GROQ_API_KEY", db_key: AI_DB_KEY_MAP.GROQ_API_KEY,
      configured: !!GROQ, priority: 25, source: src("GROQ_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.groq.com/openai/v1/chat/completions", GROQ, "gemma2-9b-it", msgs),
    },
    {
      id: "groq-llama31-8b", name: "Llama-3.1-8B Instant (Groq)", model: "llama-3.1-8b-instant",
      provider: "Groq", env_var: "GROQ_API_KEY", db_key: AI_DB_KEY_MAP.GROQ_API_KEY,
      configured: !!GROQ, priority: 26, source: src("GROQ_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.groq.com/openai/v1/chat/completions", GROQ, "llama-3.1-8b-instant", msgs),
    },
    // ── Google Gemini (free 1500 req/day) ────────────────────────────────
    {
      id: "gemini20flash", name: "Gemini-2.0-Flash", model: "gemini-2.0-flash",
      provider: "Google", env_var: "GEMINI_API_KEY", db_key: AI_DB_KEY_MAP.GEMINI_API_KEY,
      configured: !!GEMINI, priority: 12, source: src("GEMINI_API_KEY"),
      chat: (msgs) => geminiChat(GEMINI, "gemini-2.0-flash", msgs),
    },
    {
      id: "gemini15flash", name: "Gemini-1.5-Flash", model: "gemini-1.5-flash",
      provider: "Google", env_var: "GEMINI_API_KEY", db_key: AI_DB_KEY_MAP.GEMINI_API_KEY,
      configured: !!GEMINI, priority: 22, source: src("GEMINI_API_KEY"),
      chat: (msgs) => geminiChat(GEMINI, "gemini-1.5-flash", msgs),
    },
    // ── DeepSeek (free tier, strong reasoning) ───────────────────────────
    {
      id: "deepseekv3", name: "DeepSeek-V3", model: "deepseek-chat",
      provider: "DeepSeek", env_var: "DEEPSEEK_API_KEY", db_key: AI_DB_KEY_MAP.DEEPSEEK_API_KEY,
      configured: !!DEEPSEEK, priority: 13, source: src("DEEPSEEK_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.deepseek.com/chat/completions", DEEPSEEK, "deepseek-chat", msgs),
    },
    // ── Alibaba Qwen (DashScope, free tier) ──────────────────────────────
    {
      id: "qwenturbo", name: "Qwen-Turbo", model: "qwen-turbo",
      provider: "阿里云 DashScope", env_var: "DASHSCOPE_API_KEY", db_key: AI_DB_KEY_MAP.DASHSCOPE_API_KEY,
      configured: !!DASH, priority: 18, source: src("DASHSCOPE_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", DASH, "qwen-turbo", msgs),
    },
    {
      id: "qwenlong", name: "Qwen-Long", model: "qwen-long",
      provider: "阿里云 DashScope", env_var: "DASHSCOPE_API_KEY", db_key: AI_DB_KEY_MAP.DASHSCOPE_API_KEY,
      configured: !!DASH, priority: 28, source: src("DASHSCOPE_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", DASH, "qwen-long", msgs),
    },
    // ── Moonshot Kimi (free tier) ─────────────────────────────────────────
    {
      id: "kimi8k", name: "Kimi moonshot-v1-8k", model: "moonshot-v1-8k",
      provider: "月之暗面 Kimi", env_var: "MOONSHOT_API_KEY", db_key: AI_DB_KEY_MAP.MOONSHOT_API_KEY,
      configured: !!MOON, priority: 19, source: src("MOONSHOT_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.moonshot.cn/v1/chat/completions", MOON, "moonshot-v1-8k", msgs),
    },
    // ── Baidu Qianfan ERNIE (free models) ────────────────────────────────
    {
      id: "ernie-speed-8k", name: "ERNIE-Speed-8K", model: "ernie-speed-8k",
      provider: "百度千帆 Qianfan", env_var: "QIANFAN_API_KEY", db_key: AI_DB_KEY_MAP.QIANFAN_API_KEY,
      configured: !!QIANFAN, priority: 17, source: src("QIANFAN_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://qianfan.baidubce.com/v2/chat/completions", QIANFAN, "ernie-speed-8k", msgs),
    },
    {
      id: "ernie-lite-8k", name: "ERNIE-Lite-8K", model: "ernie-lite-8k",
      provider: "百度千帆 Qianfan", env_var: "QIANFAN_API_KEY", db_key: AI_DB_KEY_MAP.QIANFAN_API_KEY,
      configured: !!QIANFAN, priority: 27, source: src("QIANFAN_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://qianfan.baidubce.com/v2/chat/completions", QIANFAN, "ernie-lite-8k", msgs),
    },
    // ── SiliconFlow (free, many open models) ─────────────────────────────
    {
      id: "sili-qwen25-7b", name: "Qwen2.5-7B (SiliconFlow)", model: "Qwen/Qwen2.5-7B-Instruct",
      provider: "硅基流动 SiliconFlow", env_var: "SILICONFLOW_API_KEY", db_key: AI_DB_KEY_MAP.SILICONFLOW_API_KEY,
      configured: !!SILI, priority: 30, source: src("SILICONFLOW_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.siliconflow.cn/v1/chat/completions", SILI, "Qwen/Qwen2.5-7B-Instruct", msgs),
    },
    {
      id: "sili-llama31-8b", name: "Llama-3.1-8B (SiliconFlow)", model: "meta-llama/Meta-Llama-3.1-8B-Instruct",
      provider: "硅基流动 SiliconFlow", env_var: "SILICONFLOW_API_KEY", db_key: AI_DB_KEY_MAP.SILICONFLOW_API_KEY,
      configured: !!SILI, priority: 31, source: src("SILICONFLOW_API_KEY"),
      chat: (msgs) => openAiCompatChat(
        "https://api.siliconflow.cn/v1/chat/completions", SILI, "meta-llama/Meta-Llama-3.1-8B-Instruct", msgs),
    },
  ];

  return all.sort((a, b) => a.priority - b.priority);
}

// ─── Sync accessors (env-var only) — used by ai-models.ts for UI display ─────
export function getProviders(): AiProvider[] {
  return buildProviders();
}

export function getConfiguredProviders(): AiProvider[] {
  return buildProviders().filter(p => p.configured);
}

/** Public info only (no chat function), safe to send to frontend */
export function getProvidersInfo(): AiProviderInfo[] {
  return getProviders().map(({ id, name, model, provider, env_var, db_key, configured, priority, source }) => ({
    id, name, model, provider, env_var, db_key, configured, priority, source,
  }));
}

/** Async version that merges env vars + DB keys — used for TLD scraping */
export async function getProvidersInfoAsync(): Promise<AiProviderInfo[]> {
  const dbKeys = await loadDbKeys();
  return buildProviders(dbKeys).map(({ id, name, model, provider, env_var, db_key, configured, priority, source }) => ({
    id, name, model, provider, env_var, db_key, configured, priority, source,
  }));
}

// ─── Call context (usage audit) ───────────────────────────────────────────────
export interface AiCallContext {
  kind?: string; // e.g. "tld_extract", "hot_prefix", "generic"
  tld?: string;
}

// ─── Circuit breaker (R10): per-provider in-memory state ─────────────────────
export type CircuitStateValue = "closed" | "open" | "half_open";

export interface CircuitState {
  id: string;
  name: string;
  state: CircuitStateValue;
  consecutiveFails: number;
  firstFailTs: number;
  openUntil: number;
  transitionTs: number;
  transitions: number;
}

const FAILURE_THRESHOLD = 3;      // consecutive failures within window → open
const WINDOW_MS         = 5 * 60 * 1000;  // sliding window
const COOLDOWN_MS       = 10 * 60 * 1000; // open cooldown before half-open probe

const _circuit = new Map<string, CircuitState>();

function getCircuit(id: string, name: string): CircuitState {
  let c = _circuit.get(id);
  if (!c) {
    c = { id, name, state: "closed", consecutiveFails: 0, firstFailTs: 0, openUntil: 0, transitionTs: 0, transitions: 0 };
    _circuit.set(id, c);
  }
  return c;
}

/** Best-effort audit write to ai_call_log (R11). Never blocks the scrape pipeline. */
async function writeAiLog(entry: {
  provider: string; model: string; kind: string; tld?: string;
  ok: boolean; ms: number | null; error?: string;
}): Promise<void> {
  try {
    const { run } = await import("@/lib/db-query");
    await run(
      `INSERT INTO ai_call_log (provider, model, kind, tld, ok, ms, error)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        entry.provider,
        entry.model,
        entry.kind,
        entry.tld ?? null,
        entry.ok,
        entry.ms ?? null,
        entry.error ? entry.error.slice(0, 300) : null,
      ],
    ).catch(() => {});
  } catch {
    /* fire-and-forget */
  }
}

function logCircuitTransition(state: CircuitState, to: CircuitStateValue, reason: string): void {
  state.transitions += 1;
  state.transitionTs = Date.now();
  state.state = to;
  writeAiLog({
    provider: state.name,
    model: state.id,
    kind: "circuit",
    ok: true,
    ms: null,
    error: `circuit transition → ${to}: ${reason}`,
  }).catch(() => {});
}

/** Resolve current effective state, advancing open → half_open once cooldown lapses. */
function circuitEffectiveState(state: CircuitState): CircuitStateValue {
  if (state.state === "open" && Date.now() >= state.openUntil) {
    logCircuitTransition(state, "half_open", "cooldown elapsed, allowing single probe");
    return "half_open";
  }
  return state.state;
}

function recordCircuitFailure(state: CircuitState): void {
  const now = Date.now();
  if (now - state.firstFailTs > WINDOW_MS) {
    state.consecutiveFails = 1;
    state.firstFailTs = now;
  } else {
    state.consecutiveFails += 1;
  }
  if (state.state === "half_open") {
    logCircuitTransition(state, "open", `half-open probe failed (${state.consecutiveFails} fails in window)`);
    state.openUntil = now + COOLDOWN_MS;
  } else if (state.state === "closed" && state.consecutiveFails >= FAILURE_THRESHOLD) {
    logCircuitTransition(state, "open", `${state.consecutiveFails} consecutive failures in 5-min window`);
    state.openUntil = now + COOLDOWN_MS;
  }
}

function recordCircuitSuccess(state: CircuitState): void {
  if (state.state !== "closed") {
    logCircuitTransition(state, "closed", "probe/call succeeded");
  }
  state.consecutiveFails = 0;
  state.firstFailTs = 0;
  state.openUntil = 0;
}

/** Snapshot of circuit states — consumed by the admin AI usage page (R11 AC2). */
export function getCircuitStates(): CircuitState[] {
  return Array.from(_circuit.values()).map(c => ({ ...c }));
}

/**
 * Call providers in priority order, return first successful content string.
 * Automatically merges env vars + DB-stored keys (DB takes priority).
 * If `preferredId` is set, tries that provider first.
 *
 * R10: providers tripped open by the circuit breaker are skipped; at most one
 * half-open probe is let through per call. If everything is open, fail fast.
 * R11: every attempt (success or failure) is written to ai_call_log.
 */
export async function callProviderWithFallback(
  messages: { role: ChatRole; content: string }[],
  preferredId?: string,
  errors: string[] = [],
  ctx?: AiCallContext
): Promise<{ content: string; provider: AiProvider }> {
  const dbKeys = await loadDbKeys();
  const available = buildProviders(dbKeys).filter(p => p.configured);
  if (available.length === 0) {
    throw new Error("未配置任何 AI 提供商。请在后台「API 接入」页设置至少一个 AI Key，或配置对应环境变量。");
  }

  const kind = ctx?.kind ?? "generic";
  const tld = ctx?.tld ?? undefined;

  const ordered = preferredId
    ? [
        ...available.filter(p => p.id === preferredId),
        ...available.filter(p => p.id !== preferredId),
      ]
    : available;

  // R10: drop tripped-open providers; allow at most one half-open probe.
  const openNames: string[] = [];
  let probeAllowed = false;
  const eligible = ordered.filter(p => {
    const state = getCircuit(p.id, p.name);
    const eff = circuitEffectiveState(state);
    if (eff === "open") {
      openNames.push(p.name);
      return false;
    }
    if (eff === "half_open") {
      if (probeAllowed) return false;
      probeAllowed = true;
    }
    return true;
  });

  if (eligible.length === 0) {
    throw new Error(
      `所有可用 AI 提供商均已熔断（open：${openNames.join("、")}），请冷却后重试。`
    );
  }

  for (const provider of eligible) {
    const state = getCircuit(provider.id, provider.name);
    const started = Date.now();
    try {
      const content = await provider.chat(messages);
      await writeAiLog({
        provider: provider.name, model: provider.model, kind, tld,
        ok: true, ms: Date.now() - started,
      });
      recordCircuitSuccess(state);
      return { content, provider };
    } catch (e: any) {
      const ms = Date.now() - started;
      const message = e.message ?? String(e);
      errors.push(`[${provider.name}] ${message}`);
      await writeAiLog({
        provider: provider.name, model: provider.model, kind, tld,
        ok: false, ms, error: message,
      });
      recordCircuitFailure(state);
    }
  }

  throw new Error(`所有 AI 提供商均失败：\n${errors.join("\n")}`);
}
