import type { NextApiRequest, NextApiResponse } from "next";
import { many, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { invalidateApiConfig } from "@/lib/api-config";
import { invalidateProviders, AI_DB_KEY_MAP } from "@/lib/server/ai-providers";

// ─── Mask a key for display (show first 4 + last 4, rest as dots) ─────────────
function maskKey(k: string): string {
  if (!k) return "";
  if (k.length <= 8) return "••••••••";
  return k.slice(0, 4) + "••••" + k.slice(-4);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    try {
      const rows = await many<{ key: string; value: string }>(
        "SELECT key, value FROM site_settings WHERE key LIKE 'api_%'",
      );
      const map = Object.fromEntries(rows.map((r) => [r.key, r.value]));

      const dbYisiKey = map.api_yisi_key || "";
      const envYisiKey = process.env.YISI_API_KEY || "";
      const effectiveKey = dbYisiKey || envYisiKey;

      // Build AI provider key status
      const aiProviders: Record<string, { configured: boolean; source: "db" | "env" | null; masked: string }> = {};
      for (const [envVar, dbKey] of Object.entries(AI_DB_KEY_MAP)) {
        const dbVal = map[dbKey] || "";
        const envVal = process.env[envVar] || "";
        const effective = dbVal || envVal;
        const providerShort = envVar.replace("_API_KEY", "").toLowerCase();
        aiProviders[providerShort] = {
          configured: !!effective,
          source: dbVal ? "db" : envVal ? "env" : null,
          masked: maskKey(effective),
        };
      }

      return res.json({
        nazhumi_enabled: map.api_nazhumi_enabled !== "0",
        miqingju_enabled: map.api_miqingju_enabled !== "0",
        tianhu_enabled: map.api_tianhu_enabled !== "0",
        yisi_enabled: map.api_yisi_enabled !== "0",
        yisi_key_configured: effectiveKey.length > 0,
        yisi_key_from_env: !dbYisiKey && !!envYisiKey,
        yisi_key_masked: maskKey(effectiveKey),
        ai_providers: aiProviders,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PUT") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const body = req.body as {
      nazhumi_enabled?: boolean;
      miqingju_enabled?: boolean;
      tianhu_enabled?: boolean;
      yisi_enabled?: boolean;
      yisi_key?: string;
      // AI provider keys (keyed by short name, e.g. "zhipu", "groq", ...)
      ai_keys?: Record<string, string>;
    };

    const { nazhumi_enabled, miqingju_enabled, tianhu_enabled, yisi_enabled, yisi_key, ai_keys } = body;

    try {
      const updates: [string, string][] = [
        ["api_nazhumi_enabled", nazhumi_enabled !== false ? "1" : "0"],
        ["api_miqingju_enabled", miqingju_enabled !== false ? "1" : "0"],
        ["api_tianhu_enabled", tianhu_enabled !== false ? "1" : "0"],
        ["api_yisi_enabled", yisi_enabled !== false ? "1" : "0"],
      ];

      if (yisi_key !== undefined && !yisi_key.includes("••••")) {
        updates.push(["api_yisi_key", yisi_key.trim()]);
      }

      // AI provider keys
      if (ai_keys) {
        for (const [providerShort, keyValue] of Object.entries(ai_keys)) {
          if (keyValue.includes("••••")) continue; // skip masked placeholder
          const envVar = Object.keys(AI_DB_KEY_MAP).find(
            v => v.replace("_API_KEY", "").toLowerCase() === providerShort
          );
          if (!envVar) continue;
          const dbKey = AI_DB_KEY_MAP[envVar];
          updates.push([dbKey, keyValue.trim()]);
        }
      }

      if (updates.length > 0) {
        const placeholders = updates.map((_, i) => `($${i * 2 + 1}, $${i * 2 + 2}, NOW())`).join(", ");
        const flatParams = updates.flatMap(([k, v]) => [k, v]);
        await run(
          `INSERT INTO site_settings (key, value, updated_at) VALUES ${placeholders}
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          flatParams,
        );
      }

      invalidateApiConfig();
      // If AI keys were updated, invalidate provider cache so new keys take effect immediately
      if (ai_keys && Object.keys(ai_keys).length > 0) {
        invalidateProviders();
      }
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const { provider } = req.body as { provider?: string };
    if (!provider) return res.status(400).json({ error: "provider required" });

    const envVar = Object.keys(AI_DB_KEY_MAP).find(
      v => v.replace("_API_KEY", "").toLowerCase() === provider
    );
    if (!envVar) return res.status(400).json({ error: "unknown provider" });

    try {
      await run(`DELETE FROM site_settings WHERE key = $1`, [AI_DB_KEY_MAP[envVar]]);
      invalidateProviders();
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "POST") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const { service } = req.query;

    try {
      if (service === "nazhumi") {
        const r = await fetch(
          "https://www.nazhumi.com/api/v1?domain=com&order=new",
          { signal: AbortSignal.timeout(8000), headers: { Accept: "application/json" } },
        );
        if (!r.ok) return res.json({ ok: false, error: `HTTP ${r.status}` });
        const j = await r.json();
        const count = j.data?.price?.length ?? 0;
        return res.json({
          ok: count > 0,
          details: count > 0 ? `已获取 ${count} 条注册商数据` : "返回数据为空",
        });
      }

      if (service === "miqingju") {
        const r = await fetch(
          "https://api.miqingju.com/api/v1/query?tld=com",
          { signal: AbortSignal.timeout(8000), headers: { Accept: "application/json" } },
        );
        if (!r.ok) return res.json({ ok: false, error: `HTTP ${r.status}` });
        const j = await r.json();
        const count = j.data?.length ?? 0;
        return res.json({
          ok: !!j.success,
          details: j.success ? `已获取 ${count} 条注册商数据` : (j.message ?? "请求失败"),
        });
      }

      if (service === "tianhu") {
        const r = await fetch(
          "https://api.tian.hu/whois/google.com",
          { signal: AbortSignal.timeout(10000), headers: { Accept: "application/json" } },
        );
        if (!r.ok) return res.json({ ok: false, error: `HTTP ${r.status}` });
        const j = await r.json();
        if (j.code !== 200) return res.json({ ok: false, error: j.message || "请求失败" });
        const d = j.data?.formatted?.domain;
        const reg = j.data?.formatted?.registrar;
        return res.json({
          ok: true,
          details: `${j.data?.domain ?? "google.com"} · 注册商: ${reg?.registrar_name ?? "已返回数据"} · NS: ${(d?.name_servers ?? []).length} 条`,
        });
      }

      if (service === "yisi") {
        const rows = await many<{ value: string }>(
          "SELECT value FROM site_settings WHERE key = 'api_yisi_key'",
        );
        const dbKey = rows[0]?.value || "";
        const apiKey = dbKey || process.env.YISI_API_KEY || "";

        if (!apiKey) return res.json({ ok: false, error: "未配置 API Key" });

        let yisiRes: Response;
        try {
          yisiRes = await fetch("https://yisi.yun/api/lookup?query=google.com", {
            signal: AbortSignal.timeout(10000),
            headers: { Accept: "application/json", "x-api-key": apiKey },
          });
        } catch (connErr: any) {
          // Connection failure (DNS / network) → auto-disable so it won't be retried
          const errMsg = connErr?.message ?? String(connErr);
          await run(
            `INSERT INTO site_settings (key, value, updated_at) VALUES ('api_yisi_enabled', '0', NOW())
             ON CONFLICT (key) DO UPDATE SET value = '0', updated_at = NOW()`,
          );
          const { invalidateApiConfig } = await import("@/lib/api-config");
          invalidateApiConfig();
          return res.json({ ok: false, error: `连接失败，已自动关闭: ${errMsg}`, autoDisabled: true });
        }

        const j = await yisiRes.json();
        if (!j.status) return res.json({ ok: false, error: j.error || "请求失败" });
        return res.json({
          ok: true,
          details: `${j.result?.domain} · ${j.result?.registrar ?? "已返回数据"}`,
        });
      }

      // AI provider test — service = "ai_zhipu", "ai_groq", etc.
      if (typeof service === "string" && service.startsWith("ai_")) {
        const providerShort = service.replace("ai_", "");
        const envVar = Object.keys(AI_DB_KEY_MAP).find(
          v => v.replace("_API_KEY", "").toLowerCase() === providerShort
        );
        if (!envVar) return res.status(400).json({ ok: false, error: "未知的 AI 提供商" });

        const dbRows = await many<{ value: string }>(
          `SELECT value FROM site_settings WHERE key = $1`,
          [AI_DB_KEY_MAP[envVar]],
        );
        const effectiveKey = dbRows[0]?.value || process.env[envVar] || "";
        if (!effectiveKey) return res.json({ ok: false, error: "未配置该提供商的 API Key" });

        // Test with a lightweight echo prompt
        const testMsg = [
          { role: "system" as const, content: "You are a helpful assistant. Reply with one word only." },
          { role: "user" as const, content: "Reply with the single word: OK" },
        ];
        try {
          // Inline test using fetch directly per provider
          let testRes: Response;
          let content = "";
          if (providerShort === "gemini") {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${effectiveKey}`;
            testRes = await fetch(url, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: "Reply with the single word: OK" }] }], generationConfig: { maxOutputTokens: 5 } }),
              signal: AbortSignal.timeout(15000),
            });
            if (!testRes.ok) throw new Error(`HTTP ${testRes.status}`);
            const j = await testRes.json();
            content = j?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? "";
          } else {
            const endpoints: Record<string, [string, string]> = {
              zhipu:       ["https://open.bigmodel.cn/api/paas/v4/chat/completions", "glm-4-flashx"],
              groq:        ["https://api.groq.com/openai/v1/chat/completions", "llama-3.3-70b-versatile"],
              deepseek:    ["https://api.deepseek.com/chat/completions", "deepseek-chat"],
              dashscope:   ["https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "qwen-turbo"],
              moonshot:    ["https://api.moonshot.cn/v1/chat/completions", "moonshot-v1-8k"],
              siliconflow: ["https://api.siliconflow.cn/v1/chat/completions", "Qwen/Qwen2.5-7B-Instruct"],
              qianfan:     ["https://qianfan.baidubce.com/v2/chat/completions", "ernie-speed-8k"],
            };
            const [endpoint, model] = endpoints[providerShort] ?? ["", ""];
            if (!endpoint) throw new Error("未知提供商");
            testRes = await fetch(endpoint, {
              method: "POST",
              headers: { "Content-Type": "application/json", Authorization: `Bearer ${effectiveKey}` },
              body: JSON.stringify({ model, messages: testMsg, max_tokens: 5, temperature: 0 }),
              signal: AbortSignal.timeout(15000),
            });
            if (!testRes.ok) {
              const errText = await testRes.text().catch(() => "");
              throw new Error(`HTTP ${testRes.status}: ${errText.slice(0, 100)}`);
            }
            const j = await testRes.json();
            content = j?.choices?.[0]?.message?.content?.trim() ?? "";
          }
          return res.json({ ok: true, details: `连接成功，响应：${content || "(空)"}` });
        } catch (e: any) {
          return res.json({ ok: false, error: e.message });
        }
      }

      return res.status(400).json({ error: "unknown service" });
    } catch (err: any) {
      return res.json({ ok: false, error: err.message });
    }
  }

  res.setHeader("Allow", "GET, PUT, DELETE, POST");
  res.status(405).json({ error: "Method not allowed" });
}
