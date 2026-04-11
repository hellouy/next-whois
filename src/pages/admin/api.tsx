import React, { useEffect, useState } from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  RiLoader4Line,
  RiSaveLine,
  RiCheckLine,
  RiCloseLine,
  RiFlashlightLine,
  RiExternalLinkLine,
  RiEyeLine,
  RiEyeOffLine,
  RiPlugLine,
  RiInformationLine,
  RiRobot2Line,
  RiDeleteBinLine,
} from "@remixicon/react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AiProviderStatus {
  configured: boolean;
  source: "db" | "env" | null;
  masked: string;
}

interface ApiState {
  nazhumi_enabled: boolean;
  miqingju_enabled: boolean;
  tianhu_enabled: boolean;
  yisi_enabled: boolean;
  yisi_key_configured?: boolean;
  yisi_key_from_env?: boolean;
  yisi_key_masked?: string;
  ai_providers: Record<string, AiProviderStatus>;
}

interface TestResult {
  ok: boolean;
  details?: string;
  error?: string;
  autoDisabled?: boolean;
}

const DEFAULT_STATE: ApiState = {
  nazhumi_enabled: true,
  miqingju_enabled: true,
  tianhu_enabled: true,
  yisi_enabled: true,
  ai_providers: {},
};

// ─── AI provider metadata ────────────────────────────────────────────────────
const AI_PROVIDERS = [
  { id: "zhipu",       name: "智谱 GLM",          desc: "GLM-4-FlashX / Flash / Air",    link: "https://open.bigmodel.cn/",               color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",   priority: 1 },
  { id: "gemini",      name: "Google Gemini",      desc: "Gemini-2.0-Flash / 1.5-Flash",  link: "https://aistudio.google.com/apikey",       color: "bg-green-100 dark:bg-green-950/40 text-green-600 dark:text-green-400", priority: 2 },
  { id: "deepseek",    name: "DeepSeek",           desc: "DeepSeek-V3 (强推理)",           link: "https://platform.deepseek.com/",          color: "bg-cyan-100 dark:bg-cyan-950/40 text-cyan-600 dark:text-cyan-400",   priority: 3 },
  { id: "groq",        name: "Groq",               desc: "QwQ-32B / Llama-3.3-70B / Mixtral-8x7B / Gemma2-9B / Llama-3.1-8B", link: "https://console.groq.com/keys", color: "bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400", priority: 4 },
  { id: "dashscope",   name: "阿里云 DashScope",   desc: "Qwen-Turbo / Qwen-Long",        link: "https://dashscope.aliyun.com/",           color: "bg-yellow-100 dark:bg-yellow-950/40 text-yellow-600 dark:text-yellow-400", priority: 5 },
  { id: "moonshot",    name: "月之暗面 Kimi",       desc: "moonshot-v1-8k",                link: "https://platform.moonshot.cn/",           color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400", priority: 6 },
  { id: "siliconflow", name: "硅基流动",            desc: "Qwen2.5-7B / Llama-3.1-8B",    link: "https://cloud.siliconflow.cn/account/ak", color: "bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400",   priority: 7 },
];

// ─── Main component ──────────────────────────────────────────────────────────

export default function AdminApiPage() {
  const [state, setState] = useState<ApiState>(DEFAULT_STATE);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});

  // AI key input state per provider
  const [aiKeyInputs, setAiKeyInputs] = useState<Record<string, string>>({});
  const [aiShowKey, setAiShowKey] = useState<Record<string, boolean>>({});
  const [aiSaving, setAiSaving] = useState<string | null>(null);
  const [aiDeleting, setAiDeleting] = useState<string | null>(null);

  // Yisi key input state
  const [yisiKeyInput, setYisiKeyInput] = useState("");
  const [yisiShowKey, setYisiShowKey] = useState(false);
  const [yisiSaving, setYisiSaving] = useState(false);

  useEffect(() => {
    fetch("/api/admin/api-keys")
      .then((r) => r.json())
      .then((d) => {
        setState(d);
        setLoading(false);
      })
      .catch(() => {
        toast.error("加载配置失败");
        setLoading(false);
      });
  }, []);

  async function handleSave() {
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        nazhumi_enabled: state.nazhumi_enabled,
        miqingju_enabled: state.miqingju_enabled,
        tianhu_enabled: state.tianhu_enabled,
        yisi_enabled: state.yisi_enabled,
      };

      const r = await fetch("/api/admin/api-keys", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || "保存失败");

      toast.success("配置已保存");
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(service: string) {
    setTesting(service);
    try {
      const r = await fetch(`/api/admin/api-keys?service=${service}`, { method: "POST" });
      const d: TestResult = await r.json();
      setTestResults((prev) => ({ ...prev, [service]: d }));
      if (d.ok) {
        toast.success(`${service} 连接正常`);
      } else {
        toast.error(`${service} 测试失败：${d.error}`);
      }
    } catch (e: any) {
      setTestResults((prev) => ({ ...prev, [service]: { ok: false, error: e.message } }));
      toast.error("测试请求失败");
    } finally {
      setTesting(null);
    }
  }

  async function handleYisiKeySave() {
    const keyVal = yisiKeyInput.trim();
    if (!keyVal || keyVal.includes("••••")) return;
    setYisiSaving(true);
    try {
      const r = await fetch("/api/admin/api-keys", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nazhumi_enabled: state.nazhumi_enabled,
          miqingju_enabled: state.miqingju_enabled,
          tianhu_enabled: state.tianhu_enabled,
          yisi_enabled: state.yisi_enabled,
          yisi_key: keyVal,
        }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || "保存失败");
      const masked = keyVal.length > 8 ? keyVal.slice(0, 4) + "••••" + keyVal.slice(-4) : "••••••••";
      setState(s => ({ ...s, yisi_key_configured: true, yisi_key_from_env: false, yisi_key_masked: masked }));
      setYisiKeyInput("");
      toast.success("亿思云 API Key 已保存，即时生效");
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setYisiSaving(false);
    }
  }

  async function handleAiKeySave(providerId: string) {
    const keyVal = aiKeyInputs[providerId]?.trim();
    if (!keyVal || keyVal.includes("••••")) return;
    setAiSaving(providerId);
    try {
      const r = await fetch("/api/admin/api-keys", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nazhumi_enabled: state.nazhumi_enabled,
          miqingju_enabled: state.miqingju_enabled,
          tianhu_enabled: state.tianhu_enabled,
          yisi_enabled: state.yisi_enabled,
          ai_keys: { [providerId]: keyVal },
        }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || "保存失败");

      // Update local state
      const masked = keyVal.length > 8
        ? keyVal.slice(0, 4) + "••••" + keyVal.slice(-4)
        : "••••••••";
      setState(s => ({
        ...s,
        ai_providers: {
          ...s.ai_providers,
          [providerId]: { configured: true, source: "db", masked },
        },
      }));
      setAiKeyInputs(prev => ({ ...prev, [providerId]: "" }));
      toast.success(`${AI_PROVIDERS.find(p => p.id === providerId)?.name} Key 已保存，即时生效`);
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setAiSaving(null);
    }
  }

  async function handleAiKeyDelete(providerId: string) {
    setAiDeleting(providerId);
    try {
      const r = await fetch("/api/admin/api-keys", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: providerId }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || "删除失败");

      setState(s => ({
        ...s,
        ai_providers: {
          ...s.ai_providers,
          [providerId]: { configured: false, source: null, masked: "" },
        },
      }));
      toast.success("DB Key 已删除");
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setAiDeleting(null);
    }
  }

  if (loading) {
    return (
      <AdminLayout title="API 接入">
        <div className="flex h-64 items-center justify-center">
          <RiLoader4Line className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      </AdminLayout>
    );
  }

  const testResult = (s: string) => testResults[s];

  return (
    <AdminLayout title="API 接入">
      <div className="space-y-8 pb-32 sm:pb-10">

        {/* ── Header + Save ────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold">API 接入</h1>
            <p className="mt-0.5 text-sm text-muted-foreground">
              管理第三方数据源开关、认证信息，以及 AI 提供商 Key
            </p>
          </div>
          <Button onClick={handleSave} disabled={saving} size="sm">
            {saving ? (
              <RiLoader4Line className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <RiSaveLine className="mr-1.5 h-4 w-4" />
            )}
            保存开关
          </Button>
        </div>

        {/* ── AI 提供商 Key 管理 ─────────────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <RiRobot2Line className="h-5 w-5 text-primary" />
            <h2 className="font-semibold text-base">AI 提供商 Key</h2>
            <span className="text-xs text-muted-foreground">— 用于 TLD 生命周期爬取，写入即时生效</span>
          </div>

          <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
            <div className="divide-y divide-border">
              {AI_PROVIDERS.sort((a, b) => a.priority - b.priority).map((provider) => {
                const status = state.ai_providers[provider.id];
                const inputVal = aiKeyInputs[provider.id] ?? "";
                const showInput = inputVal !== "" || !status?.configured;
                const isLoading = aiSaving === provider.id || aiDeleting === provider.id || testing === `ai_${provider.id}`;

                return (
                  <div key={provider.id} className="px-5 py-4">
                    <div className="flex items-start gap-3">
                      {/* Icon */}
                      <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${provider.color}`}>
                        <RiRobot2Line className="h-4 w-4" />
                      </div>

                      {/* Info + controls */}
                      <div className="flex-1 min-w-0 space-y-2">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-sm">{provider.name}</span>
                            <span className="text-xs text-muted-foreground">{provider.desc}</span>
                            <a
                              href={provider.link}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-muted-foreground hover:text-foreground"
                            >
                              <RiExternalLinkLine className="h-3.5 w-3.5" />
                            </a>
                          </div>
                          <div className="flex items-center gap-2">
                            {status?.source === "env" && (
                              <span className="text-xs text-muted-foreground flex items-center gap-1">
                                <RiInformationLine className="h-3 w-3" />
                                来自环境变量
                              </span>
                            )}
                            <Badge
                              variant="outline"
                              className={
                                status?.configured
                                  ? "border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400"
                                  : "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-400"
                              }
                            >
                              {status?.configured ? (
                                <><RiCheckLine className="mr-1 h-3 w-3" />已配置</>
                              ) : (
                                <><RiCloseLine className="mr-1 h-3 w-3" />未配置</>
                              )}
                            </Badge>
                          </div>
                        </div>

                        {/* Current masked key display */}
                        {status?.configured && status.source === "db" && !inputVal && (
                          <div className="flex items-center gap-2">
                            <div className="flex-1 flex items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-1.5 text-sm font-mono text-muted-foreground">
                              <span>{status.masked}</span>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-8 text-xs"
                              onClick={() => setAiKeyInputs(p => ({ ...p, [provider.id]: " " }))}
                            >
                              更换
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-8 text-xs text-destructive hover:text-destructive"
                              disabled={aiDeleting === provider.id}
                              onClick={() => handleAiKeyDelete(provider.id)}
                            >
                              {aiDeleting === provider.id ? (
                                <RiLoader4Line className="h-3.5 w-3.5 animate-spin" />
                              ) : (
                                <RiDeleteBinLine className="h-3.5 w-3.5" />
                              )}
                            </Button>
                          </div>
                        )}

                        {/* Key input */}
                        {showInput && (
                          <div className="flex items-center gap-2">
                            <div className="relative flex-1">
                              <Input
                                type={aiShowKey[provider.id] ? "text" : "password"}
                                placeholder={`粘贴 ${provider.name} API Key`}
                                value={inputVal.trim()}
                                onChange={(e) => setAiKeyInputs(p => ({ ...p, [provider.id]: e.target.value }))}
                                className="pr-10 font-mono text-sm"
                                autoComplete="off"
                              />
                              <button
                                type="button"
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                                onClick={() => setAiShowKey(p => ({ ...p, [provider.id]: !p[provider.id] }))}
                              >
                                {aiShowKey[provider.id] ? (
                                  <RiEyeOffLine className="h-4 w-4" />
                                ) : (
                                  <RiEyeLine className="h-4 w-4" />
                                )}
                              </button>
                            </div>
                            <Button
                              size="sm"
                              disabled={!inputVal.trim() || inputVal.trim().includes("••••") || aiSaving === provider.id}
                              onClick={() => handleAiKeySave(provider.id)}
                            >
                              {aiSaving === provider.id ? (
                                <RiLoader4Line className="mr-1.5 h-4 w-4 animate-spin" />
                              ) : (
                                <RiSaveLine className="mr-1.5 h-4 w-4" />
                              )}
                              保存
                            </Button>
                            {status?.configured && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setAiKeyInputs(p => ({ ...p, [provider.id]: "" }))}
                              >
                                取消
                              </Button>
                            )}
                          </div>
                        )}

                        {/* Test button */}
                        {status?.configured && (
                          <div className="flex items-center gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              className="h-7 text-xs"
                              disabled={isLoading}
                              onClick={() => handleTest(`ai_${provider.id}`)}
                            >
                              {testing === `ai_${provider.id}` ? (
                                <RiLoader4Line className="mr-1 h-3.5 w-3.5 animate-spin" />
                              ) : (
                                <RiFlashlightLine className="mr-1 h-3.5 w-3.5" />
                              )}
                              测试连接
                            </Button>
                            {testResult(`ai_${provider.id}`) && (
                              <span className={`text-xs ${testResult(`ai_${provider.id}`)!.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}>
                                {testResult(`ai_${provider.id}`)!.ok
                                  ? testResult(`ai_${provider.id}`)!.details ?? "连接成功"
                                  : testResult(`ai_${provider.id}`)!.error ?? "连接失败"}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="px-5 py-3 border-t border-border bg-muted/30">
              <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                <RiInformationLine className="h-3.5 w-3.5 shrink-0" />
                DB Key 保存后立即生效（无需重启），优先级高于同名环境变量。多个 Key 按优先级自动降级。
              </p>
            </div>
          </div>
        </section>

        {/* ── WHOIS / 数据源 ────────────────────────────────────────── */}
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <RiPlugLine className="h-5 w-5 text-primary" />
            <h2 className="font-semibold text-base">WHOIS / 数据源</h2>
          </div>

          <ServiceCard
            color="bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400"
            dot="bg-blue-500"
            name="哪煮米"
            name_en="nazhumi.com"
            desc="域名注册价格比价（人工维护，数据精准）"
            link="https://www.nazhumi.com"
            apiDocsLink="https://www.nazhumi.com/api"
            noKey
            enabled={state.nazhumi_enabled}
            onToggle={(v) => setState((s) => ({ ...s, nazhumi_enabled: v }))}
            onTest={() => handleTest("nazhumi")}
            testing={testing === "nazhumi"}
            testResult={testResult("nazhumi")}
          />

          <ServiceCard
            color="bg-teal-100 dark:bg-teal-950/40 text-teal-600 dark:text-teal-400"
            dot="bg-teal-500"
            name="米情局"
            name_en="miqingju.com"
            desc="域名注册价格比价（脚本自动更新，覆盖面广）"
            link="https://miqingju.com"
            apiDocsLink="https://api.miqingju.com"
            noKey
            enabled={state.miqingju_enabled}
            onToggle={(v) => setState((s) => ({ ...s, miqingju_enabled: v }))}
            onTest={() => handleTest("miqingju")}
            testing={testing === "miqingju"}
            testResult={testResult("miqingju")}
          />

          <ServiceCard
            color="bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400"
            dot="bg-orange-500"
            name="天虎"
            name_en="tian.hu"
            desc="WHOIS 查询（免费公开接口，覆盖主流 TLD）"
            link="https://tian.hu"
            apiDocsLink="https://tian.hu"
            noKey
            enabled={state.tianhu_enabled}
            onToggle={(v) => setState((s) => ({ ...s, tianhu_enabled: v }))}
            onTest={() => handleTest("tianhu")}
            testing={testing === "tianhu"}
            testResult={testResult("tianhu")}
          />

          <ServiceCard
            color="bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400"
            dot="bg-violet-500"
            name="亿思云"
            name_en="yisi.yun"
            desc="WHOIS 查询（需要 API Key，覆盖冷门 TLD）"
            link="https://yisi.yun"
            enabled={state.yisi_enabled}
            onToggle={(v) => setState((s) => ({ ...s, yisi_enabled: v }))}
            onTest={() => handleTest("yisi")}
            testing={testing === "yisi"}
            testResult={testResult("yisi")}
          >
            {/* Yisi API Key management */}
            <div className="space-y-2">
              {state.yisi_key_configured && !yisiKeyInput ? (
                <div className="flex items-center gap-2">
                  <div className="flex-1 flex items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-1.5 text-sm font-mono text-muted-foreground">
                    <span>{state.yisi_key_masked}</span>
                    {state.yisi_key_from_env && (
                      <span className="text-[10px] text-muted-foreground/60 ml-1">来自环境变量</span>
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="shrink-0"
                    onClick={() => setYisiKeyInput(" ")}
                  >
                    更换
                  </Button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Input
                      type={yisiShowKey ? "text" : "password"}
                      value={yisiKeyInput.trim() === "" ? "" : yisiKeyInput}
                      onChange={e => setYisiKeyInput(e.target.value)}
                      placeholder="粘贴亿思云 API Key…"
                      className="pr-8 text-sm font-mono"
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      onClick={() => setYisiShowKey(v => !v)}
                    >
                      {yisiShowKey ? <RiEyeOffLine className="h-3.5 w-3.5" /> : <RiEyeLine className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  <Button
                    size="sm"
                    disabled={!yisiKeyInput.trim() || yisiKeyInput.trim().includes("••••") || yisiSaving}
                    onClick={handleYisiKeySave}
                  >
                    {yisiSaving ? <RiLoader4Line className="mr-1.5 h-4 w-4 animate-spin" /> : <RiSaveLine className="mr-1.5 h-4 w-4" />}
                    保存
                  </Button>
                  {state.yisi_key_configured && (
                    <Button variant="ghost" size="sm" onClick={() => setYisiKeyInput("")}>取消</Button>
                  )}
                </div>
              )}
              <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                <RiInformationLine className="h-3.5 w-3.5 shrink-0" />
                DB Key 保存后即时生效。也可通过环境变量 <code className="font-mono text-[11px]">YISI_API_KEY</code> 配置。
              </p>
            </div>
          </ServiceCard>

        </section>
      </div>
    </AdminLayout>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function ServiceCard({
  color,
  name,
  name_en,
  desc,
  link,
  apiDocsLink,
  noKey,
  enabled,
  onToggle,
  onTest,
  testing,
  testResult,
  children,
}: {
  color: string;
  dot: string;
  name: string;
  name_en: string;
  desc: string;
  link: string;
  apiDocsLink?: string;
  noKey?: boolean;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onTest: () => void;
  testing: boolean;
  testResult?: TestResult;
  children?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border bg-card shadow-sm">
      <div className="flex items-center justify-between gap-4 border-b border-border px-5 py-4">
        <div className="flex items-center gap-3">
          <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${color}`}>
            <RiPlugLine className="h-4.5 w-4.5" />
          </div>
          <div>
            <div className="flex items-center gap-2 font-semibold text-sm">
              {name}
              <span className="text-xs font-normal text-muted-foreground">{name_en}</span>
              <a
                href={link}
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <RiExternalLinkLine className="h-3.5 w-3.5" />
              </a>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant="outline"
            className={
              enabled
                ? "border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400"
                : "border-zinc-300 bg-zinc-50 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-400"
            }
          >
            {enabled ? (
              <RiCheckLine className="mr-1 h-3 w-3" />
            ) : (
              <RiCloseLine className="mr-1 h-3 w-3" />
            )}
            {enabled ? "已启用" : "已禁用"}
          </Badge>
          <Switch checked={enabled} onCheckedChange={onToggle} />
        </div>
      </div>

      <div className="px-5 py-4 space-y-3">
        {noKey && (
          <p className="text-xs text-muted-foreground flex items-center gap-1.5">
            <RiInformationLine className="h-3.5 w-3.5 shrink-0" />
            免费公开 API，无需 Key
            {apiDocsLink && (
              <>
                {" · "}
                <a
                  href={apiDocsLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  接口文档
                </a>
              </>
            )}
          </p>
        )}

        {children}

        {testResult && <TestResultBanner result={testResult} />}

        <div className="flex justify-end">
          <Button
            variant="outline"
            size="sm"
            onClick={onTest}
            disabled={testing || !enabled}
          >
            {testing ? (
              <RiLoader4Line className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <RiFlashlightLine className="mr-1.5 h-4 w-4" />
            )}
            测试连接
          </Button>
        </div>
      </div>
    </div>
  );
}

function TestResultBanner({ result }: { result: TestResult }) {
  return (
    <div
      className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${
        result.ok
          ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-400"
          : "border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/30 dark:text-red-400"
      }`}
    >
      {result.ok ? (
        <RiCheckLine className="mt-0.5 h-4 w-4 shrink-0" />
      ) : (
        <RiCloseLine className="mt-0.5 h-4 w-4 shrink-0" />
      )}
      <span>{result.ok ? (result.details ?? "连接成功") : (result.error ?? "连接失败")}</span>
    </div>
  );
}
