/**
 * /api/admin/hot-prefixes — CRUD for managing hot domain prefix watchlist.
 *
 * Hot prefixes are domain name parts (SLDs) that are currently trending and
 * likely to have high resale value. When a user queries a domain whose name
 * matches a hot prefix + premium TLD combination and it's available, the admin
 * gets an email alert.
 *
 * GET    → list all prefixes (paginated, filterable)
 * POST   → create / seed
 * PATCH  → update one
 * DELETE → delete one
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { redis, isRedisAvailable } from "@/lib/server/redis";

export const HOT_PREFIX_CACHE_KEY = "hot_prefixes_v1";
export const HOT_PREFIX_CACHE_TTL = 300; // 5 minutes

/** Seed data: curated list of currently high-value domain prefixes */
export const SEED_PREFIXES: Array<{
  prefix: string; category: string; weight: number; source: string; sale_examples?: string; notes?: string;
}> = [
  // ── AI / LLM ──────────────────────────────────────────────────────────────
  { prefix: "ai",         category: "ai",      weight: 30, source: "manual", sale_examples: "ai.com ~$1.5M", notes: "Most valuable AI prefix" },
  { prefix: "gpt",        category: "ai",      weight: 28, source: "manual", sale_examples: "gpt.io ~$50k" },
  { prefix: "llm",        category: "ai",      weight: 26, source: "manual" },
  { prefix: "agi",        category: "ai",      weight: 25, source: "manual" },
  { prefix: "agent",      category: "ai",      weight: 24, source: "manual", notes: "AI agent trend 2024-2025" },
  { prefix: "agents",     category: "ai",      weight: 22, source: "manual" },
  { prefix: "chatbot",    category: "ai",      weight: 20, source: "manual" },
  { prefix: "copilot",    category: "ai",      weight: 22, source: "manual", notes: "GitHub Copilot brand association" },
  { prefix: "cursor",     category: "ai",      weight: 22, source: "manual", notes: "AI code editor trend" },
  { prefix: "manus",      category: "ai",      weight: 22, source: "manual", notes: "Emerging AI agent platform" },
  { prefix: "devin",      category: "ai",      weight: 20, source: "manual", notes: "AI software engineer" },
  { prefix: "claude",     category: "ai",      weight: 22, source: "manual", notes: "Anthropic model name" },
  { prefix: "gemini",     category: "ai",      weight: 20, source: "manual", notes: "Google AI model" },
  { prefix: "deepseek",   category: "ai",      weight: 22, source: "manual", notes: "Chinese AI lab 2025 trending" },
  { prefix: "sora",       category: "ai",      weight: 20, source: "manual", notes: "OpenAI video model" },
  { prefix: "rag",        category: "ai",      weight: 22, source: "manual", notes: "Retrieval-Augmented Generation" },
  { prefix: "vector",     category: "ai",      weight: 18, source: "manual", notes: "Vector DB / embeddings trend" },
  { prefix: "embed",      category: "ai",      weight: 16, source: "manual" },
  { prefix: "inference",  category: "ai",      weight: 16, source: "manual" },
  { prefix: "diffusion",  category: "ai",      weight: 18, source: "manual", notes: "Stable Diffusion ecosystem" },
  { prefix: "openai",     category: "ai",      weight: 25, source: "manual", notes: "Brand keyword" },
  { prefix: "anthropic",  category: "ai",      weight: 23, source: "manual" },
  { prefix: "perplexity", category: "ai",      weight: 20, source: "manual" },
  { prefix: "mistral",    category: "ai",      weight: 18, source: "manual" },
  { prefix: "llama",      category: "ai",      weight: 18, source: "manual" },
  { prefix: "runway",     category: "ai",      weight: 16, source: "manual" },
  // ── Web3 / Crypto ─────────────────────────────────────────────────────────
  { prefix: "defi",       category: "web3",    weight: 22, source: "manual", notes: "DeFi trend" },
  { prefix: "web3",       category: "web3",    weight: 22, source: "manual" },
  { prefix: "nft",        category: "web3",    weight: 20, source: "manual", sale_examples: "nft.com $15M" },
  { prefix: "dao",        category: "web3",    weight: 20, source: "manual" },
  { prefix: "crypto",     category: "web3",    weight: 22, source: "manual", sale_examples: "crypto.com $12M" },
  { prefix: "zk",         category: "web3",    weight: 24, source: "manual", notes: "ZK-proof trend 2024-2025" },
  { prefix: "token",      category: "web3",    weight: 22, source: "manual" },
  { prefix: "wallet",     category: "web3",    weight: 20, source: "manual" },
  { prefix: "chain",      category: "web3",    weight: 18, source: "manual" },
  { prefix: "eigen",      category: "web3",    weight: 22, source: "manual", notes: "EigenLayer restaking trend" },
  { prefix: "restake",    category: "web3",    weight: 20, source: "manual" },
  { prefix: "stake",      category: "web3",    weight: 16, source: "manual" },
  { prefix: "dex",        category: "web3",    weight: 18, source: "manual" },
  { prefix: "swap",       category: "web3",    weight: 16, source: "manual" },
  { prefix: "bridge",     category: "web3",    weight: 16, source: "manual" },
  { prefix: "rollup",     category: "web3",    weight: 18, source: "manual" },
  { prefix: "celestia",   category: "web3",    weight: 18, source: "manual", notes: "Modular blockchain" },
  { prefix: "hyperliquid", category: "web3",   weight: 18, source: "manual", notes: "Trending DEX 2024" },
  // ── Finance / Fintech ─────────────────────────────────────────────────────
  { prefix: "pay",        category: "finance", weight: 26, source: "manual", sale_examples: "pay.com $8M" },
  { prefix: "payment",    category: "finance", weight: 22, source: "manual" },
  { prefix: "payments",   category: "finance", weight: 20, source: "manual" },
  { prefix: "bank",       category: "finance", weight: 22, source: "manual", sale_examples: "bank.com $11M" },
  { prefix: "fintech",    category: "finance", weight: 20, source: "manual" },
  { prefix: "invest",     category: "finance", weight: 18, source: "manual" },
  { prefix: "fund",       category: "finance", weight: 16, source: "manual" },
  { prefix: "wealth",     category: "finance", weight: 18, source: "manual" },
  { prefix: "trade",      category: "finance", weight: 18, source: "manual" },
  { prefix: "lending",    category: "finance", weight: 16, source: "manual" },
  // ── SaaS / DevTools ───────────────────────────────────────────────────────
  { prefix: "api",        category: "saas",    weight: 26, source: "manual", notes: "Always high value" },
  { prefix: "sdk",        category: "saas",    weight: 20, source: "manual" },
  { prefix: "dev",        category: "saas",    weight: 20, source: "manual", sale_examples: "dev.com $500k" },
  { prefix: "cloud",      category: "saas",    weight: 20, source: "manual", sale_examples: "cloud.com $1.7M" },
  { prefix: "hub",        category: "saas",    weight: 18, source: "manual" },
  { prefix: "platform",   category: "saas",    weight: 16, source: "manual" },
  { prefix: "studio",     category: "saas",    weight: 16, source: "manual" },
  { prefix: "flow",       category: "saas",    weight: 16, source: "manual" },
  { prefix: "forge",      category: "saas",    weight: 16, source: "manual" },
  { prefix: "kit",        category: "saas",    weight: 14, source: "manual" },
  { prefix: "saas",       category: "saas",    weight: 18, source: "manual" },
  // ── Short / Premium ───────────────────────────────────────────────────────
  { prefix: "x",          category: "short",   weight: 30, source: "manual", sale_examples: "x.com — acquired by Elon for Twitter rebrand" },
  { prefix: "go",         category: "short",   weight: 24, source: "manual" },
  { prefix: "my",         category: "short",   weight: 20, source: "manual" },
  { prefix: "me",         category: "short",   weight: 20, source: "manual" },
  { prefix: "io",         category: "short",   weight: 22, source: "manual" },
  { prefix: "co",         category: "short",   weight: 20, source: "manual" },
  { prefix: "pro",        category: "short",   weight: 18, source: "manual" },
  { prefix: "app",        category: "short",   weight: 20, source: "manual" },
  // ── Chinese Market ────────────────────────────────────────────────────────
  { prefix: "baidu",      category: "cn",      weight: 22, source: "manual", notes: "Major CN brand" },
  { prefix: "alipay",     category: "cn",      weight: 22, source: "manual" },
  { prefix: "wechat",     category: "cn",      weight: 22, source: "manual" },
  { prefix: "taobao",     category: "cn",      weight: 20, source: "manual" },
  { prefix: "jd",         category: "cn",      weight: 18, source: "manual" },
  { prefix: "renren",     category: "cn",      weight: 14, source: "manual" },
];

let _schemaReady = false;
async function ensureSchema() {
  if (_schemaReady) return;
  await run(`
    CREATE TABLE IF NOT EXISTS hot_prefixes (
      id         SERIAL PRIMARY KEY,
      prefix     VARCHAR(100) NOT NULL,
      category   VARCHAR(50)  NOT NULL DEFAULT 'general',
      weight     INT          NOT NULL DEFAULT 10,
      source     VARCHAR(100) NOT NULL DEFAULT 'manual',
      sale_examples TEXT,
      notes      TEXT,
      enabled    BOOLEAN      NOT NULL DEFAULT true,
      hit_count  INT          NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      CONSTRAINT hot_prefixes_prefix_uniq UNIQUE (prefix)
    )
  `);
  _schemaReady = true;
}

async function invalidateCache() {
  if (!isRedisAvailable() || !redis) return;
  try {
    await redis.del(HOT_PREFIX_CACHE_KEY);
  } catch { /* ignore */ }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  try {
    await ensureSchema();
  } catch (e: any) {
    return res.status(500).json({ error: `DB schema error: ${e.message}` });
  }

  // ── GET: list all prefixes ────────────────────────────────────────────────
  if (req.method === "GET") {
    const { search, category, action } = req.query;

    // Seed action
    if (action === "seed") {
      const results = await Promise.allSettled(
        SEED_PREFIXES.map(p =>
          run(
            `INSERT INTO hot_prefixes (prefix, category, weight, source, sale_examples, notes)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (prefix) DO NOTHING`,
            [p.prefix, p.category, p.weight, p.source, p.sale_examples ?? null, p.notes ?? null],
          )
        )
      );
      const seeded = results.filter(r => r.status === "fulfilled").length;
      await invalidateCache();
      return res.status(200).json({ ok: true, seeded });
    }

    let sql = `SELECT *, (SELECT COUNT(*) FROM search_history sh
               WHERE sh.query_type='domain'
               AND split_part(sh.query,'.',1) = hp.prefix
               AND sh.created_at >= NOW() - INTERVAL '30 days') AS recent_hits
               FROM hot_prefixes hp WHERE 1=1`;
    const params: (string | number)[] = [];
    let idx = 1;
    if (search && typeof search === "string" && search.trim()) {
      sql += ` AND prefix ILIKE $${idx}`;
      params.push(`%${search.trim()}%`);
      idx++;
    }
    if (category && typeof category === "string" && category !== "all") {
      sql += ` AND category = $${idx}`;
      params.push(category);
      idx++;
    }
    sql += ` ORDER BY weight DESC, prefix ASC`;

    const [rows, total, categories] = await Promise.all([
      many(sql, params),
      one<{ count: string }>(`SELECT COUNT(*) AS count FROM hot_prefixes`, []),
      many<{ category: string; cnt: string }>(
        `SELECT category, COUNT(*) AS cnt FROM hot_prefixes GROUP BY category ORDER BY cnt DESC`, []
      ),
    ]);
    return res.status(200).json({ prefixes: rows, total: parseInt(total?.count ?? "0"), categories });
  }

  // ── POST: create new prefix ───────────────────────────────────────────────
  if (req.method === "POST") {
    const { prefix, category, weight, source, sale_examples, notes, enabled } = req.body ?? {};
    if (!prefix || typeof prefix !== "string") return res.status(400).json({ error: "prefix 必填" });
    const cleanPrefix = prefix.toLowerCase().trim().replace(/[^a-z0-9-]/g, "");
    if (!cleanPrefix) return res.status(400).json({ error: "prefix 格式无效" });

    try {
      const row = await one(
        `INSERT INTO hot_prefixes (prefix, category, weight, source, sale_examples, notes, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (prefix) DO UPDATE SET
           category = EXCLUDED.category,
           weight   = EXCLUDED.weight,
           source   = EXCLUDED.source,
           sale_examples = EXCLUDED.sale_examples,
           notes    = EXCLUDED.notes,
           enabled  = EXCLUDED.enabled,
           updated_at = NOW()
         RETURNING *`,
        [
          cleanPrefix,
          category ?? "general",
          Math.min(30, Math.max(1, parseInt(weight) || 10)),
          source ?? "manual",
          sale_examples ?? null,
          notes ?? null,
          enabled !== false,
        ],
      );
      await invalidateCache();
      return res.status(200).json({ ok: true, prefix: row });
    } catch (e: any) {
      return res.status(500).json({ error: e.message });
    }
  }

  // ── PATCH: update one prefix ──────────────────────────────────────────────
  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "id 必填" });
    const { category, weight, source, sale_examples, notes, enabled } = req.body ?? {};

    const updates: string[] = [];
    const params: (string | number | boolean | null)[] = [];
    let idx = 1;

    if (category !== undefined)       { updates.push(`category = $${idx++}`);       params.push(category); }
    if (weight !== undefined)         { updates.push(`weight = $${idx++}`);         params.push(Math.min(30, Math.max(1, parseInt(weight) || 10))); }
    if (source !== undefined)         { updates.push(`source = $${idx++}`);         params.push(source); }
    if (sale_examples !== undefined)  { updates.push(`sale_examples = $${idx++}`);  params.push(sale_examples ?? null); }
    if (notes !== undefined)          { updates.push(`notes = $${idx++}`);          params.push(notes ?? null); }
    if (enabled !== undefined)        { updates.push(`enabled = $${idx++}`);        params.push(Boolean(enabled)); }

    if (updates.length === 0) return res.status(400).json({ error: "无更新字段" });
    updates.push(`updated_at = NOW()`);
    params.push(id);

    try {
      const row = await one(`UPDATE hot_prefixes SET ${updates.join(", ")} WHERE id = $${idx} RETURNING *`, params);
      await invalidateCache();
      return res.status(200).json({ ok: true, prefix: row });
    } catch (e: any) {
      return res.status(500).json({ error: e.message });
    }
  }

  // ── DELETE: remove one prefix ─────────────────────────────────────────────
  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "id 必填" });
    try {
      await run(`DELETE FROM hot_prefixes WHERE id = $1`, [id]);
      await invalidateCache();
      return res.status(200).json({ ok: true });
    } catch (e: any) {
      return res.status(500).json({ error: e.message });
    }
  }

  return res.status(405).json({ error: "Method not allowed" });
}
