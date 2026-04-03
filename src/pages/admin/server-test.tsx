import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line,
  RiCheckLine,
  RiErrorWarningLine,
  RiServerLine,
  RiWifiLine,
  RiAddLine,
  RiTimeLine,
  RiInformationLine,
} from "@remixicon/react";

type ServerType = "tcp" | "http";

type TestResult = {
  ok: boolean;
  method: string;
  output?: string;
  statusCode?: number;
  error?: string;
  elapsedMs: number;
};

export default function ServerTestPage() {
  const [tld, setTld] = React.useState("");
  const [serverType, setServerType] = React.useState<ServerType>("tcp");

  const [tcpHost, setTcpHost] = React.useState("");
  const [tcpPort, setTcpPort] = React.useState("");

  const [httpUrl, setHttpUrl] = React.useState("");

  const [testing, setTesting] = React.useState(false);
  const [result, setResult] = React.useState<TestResult | null>(null);

  const [saving, setSaving] = React.useState(false);

  const normalizedTld = tld.trim().toLowerCase().replace(/^\./, "");

  function buildEntry() {
    if (serverType === "tcp") {
      const rawPort = tcpPort.trim();
      let port: number | undefined;
      if (rawPort) {
        const parsed = parseInt(rawPort, 10);
        if (Number.isNaN(parsed) || parsed < 1 || parsed > 65535) return null;
        port = parsed;
      }
      return {
        type: "tcp" as const,
        host: tcpHost.trim(),
        ...(port !== undefined ? { port } : {}),
      };
    } else {
      return {
        type: "http" as const,
        url: httpUrl.trim(),
        method: "GET" as const,
      };
    }
  }

  function isFormValid() {
    if (!normalizedTld) return false;
    if (serverType === "tcp") return tcpHost.trim().length > 0;
    if (serverType === "http") return httpUrl.trim().length > 0;
    return false;
  }

  async function runTest() {
    if (!isFormValid()) return;
    const entry = buildEntry();
    if (!entry) {
      toast.error("端口号格式不正确");
      return;
    }

    setTesting(true);
    setResult(null);

    try {
      const res = await fetch("/api/admin/test-server", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld: normalizedTld, entry }),
      });
      const data: TestResult = await res.json();
      setResult(data);
      if (!res.ok && !data.method) {
        toast.error(data.error || "测试请求失败");
      }
    } catch {
      toast.error("请求失败，请检查网络");
    } finally {
      setTesting(false);
    }
  }

  async function saveServer() {
    if (!result?.ok) return;
    const entry = buildEntry();
    if (!entry) return;

    setSaving(true);
    try {
      const res = await fetch("/api/admin/tld-servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld: normalizedTld, entry }),
      });
      const data = await res.json();
      if (data.success) {
        toast.success(data.message || `已保存 .${normalizedTld} 服务器配置`);
      } else {
        toast.error(data.message || "保存失败");
      }
    } catch {
      toast.error("保存请求失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <AdminLayout title="服务器测试">
      <div className="space-y-5">

        <div>
          <h2 className="text-lg font-bold flex items-center gap-2">
            <RiWifiLine className="w-5 h-5 text-sky-500" />
            WHOIS 服务器连通性测试
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            输入域名后缀和服务器地址，发起实时查询验证服务器是否可用，确认后一键添加
          </p>
        </div>

        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
            <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400">
              <RiServerLine className="w-3.5 h-3.5" />
            </div>
            <h3 className="text-sm font-bold">测试参数</h3>
          </div>

          <div className="p-5 space-y-4">
            {/* TLD field */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-muted-foreground">域名后缀 (TLD)</label>
              <Input
                placeholder="例如：com 或 .io"
                value={tld}
                onChange={e => { setTld(e.target.value); setResult(null); }}
                className="h-9 text-sm rounded-xl font-mono"
              />
              {normalizedTld && (
                <p className="text-[10px] text-muted-foreground">
                  将查询：<code className="font-mono">example.{normalizedTld}</code>
                </p>
              )}
            </div>

            {/* Server type selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-muted-foreground">服务器类型</label>
              <div className="flex gap-2">
                {(["tcp", "http"] as ServerType[]).map(type => (
                  <button
                    key={type}
                    onClick={() => { setServerType(type); setResult(null); }}
                    className={cn(
                      "flex-1 h-9 rounded-xl text-sm font-semibold border transition-all",
                      serverType === type
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-background border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
                    )}
                  >
                    {type === "tcp" ? "TCP WHOIS (端口 43)" : "HTTP / RDAP"}
                  </button>
                ))}
              </div>
            </div>

            {/* TCP fields */}
            {serverType === "tcp" && (
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground">主机名 / IP</label>
                  <Input
                    placeholder="例如：whois.verisign-grs.com"
                    value={tcpHost}
                    onChange={e => { setTcpHost(e.target.value); setResult(null); }}
                    className="h-9 text-sm rounded-xl font-mono"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground">端口（可选）</label>
                  <Input
                    placeholder="43"
                    value={tcpPort}
                    onChange={e => { setTcpPort(e.target.value); setResult(null); }}
                    className="h-9 text-sm rounded-xl font-mono"
                    type="number"
                    min={1}
                    max={65535}
                  />
                </div>
              </div>
            )}

            {/* HTTP fields */}
            {serverType === "http" && (
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-muted-foreground">RDAP / HTTP URL</label>
                <Input
                  placeholder="例如：https://rdap.verisign.com/com/v1/domain/"
                  value={httpUrl}
                  onChange={e => { setHttpUrl(e.target.value); setResult(null); }}
                  className="h-9 text-sm rounded-xl font-mono"
                />
                <p className="text-[10px] text-muted-foreground">
                  将在 URL 末尾自动拼接 <code className="font-mono">example.{normalizedTld || "tld"}</code> 进行查询
                </p>
              </div>
            )}

            {/* Test button */}
            <Button
              onClick={runTest}
              disabled={testing || !isFormValid()}
              className="w-full h-10 rounded-xl gap-2"
            >
              {testing
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : <RiWifiLine className="w-4 h-4" />}
              {testing ? "测试中…" : "测试连接"}
            </Button>
          </div>
        </div>

        {/* Result panel */}
        {result && (
          <div className={cn(
            "glass-panel border rounded-2xl overflow-hidden",
            result.ok
              ? "border-emerald-200 dark:border-emerald-800/40"
              : "border-red-200 dark:border-red-800/40"
          )}>
            <div className={cn(
              "px-5 py-3 flex items-center gap-3 border-b",
              result.ok
                ? "bg-emerald-50/60 dark:bg-emerald-950/20 border-emerald-200/60 dark:border-emerald-800/30"
                : "bg-red-50/60 dark:bg-red-950/20 border-red-200/60 dark:border-red-800/30"
            )}>
              <div className={cn(
                "w-7 h-7 rounded-xl flex items-center justify-center shrink-0",
                result.ok
                  ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600"
                  : "bg-red-100 dark:bg-red-950/40 text-red-600"
              )}>
                {result.ok
                  ? <RiCheckLine className="w-4 h-4" />
                  : <RiErrorWarningLine className="w-4 h-4" />}
              </div>
              <div className="flex-1 min-w-0">
                <p className={cn(
                  "text-sm font-bold",
                  result.ok ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"
                )}>
                  {result.ok ? "连接成功" : "连接失败"}
                </p>
                <p className="text-[11px] text-muted-foreground">
                  协议：{result.method}
                  {result.statusCode != null && ` · HTTP ${result.statusCode}`}
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <RiTimeLine className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-xs font-mono font-semibold text-muted-foreground">
                  {result.elapsedMs} ms
                </span>
              </div>
            </div>

            {/* Error message */}
            {result.error && (
              <div className="px-5 py-3 border-b border-border/50 flex items-start gap-2">
                <RiErrorWarningLine className="w-3.5 h-3.5 text-red-500 shrink-0 mt-0.5" />
                <p className="text-xs text-red-600 dark:text-red-400 break-all">{result.error}</p>
              </div>
            )}

            {/* Raw output preview */}
            {result.output && (
              <div className="px-5 py-4">
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">
                  响应内容预览
                </p>
                <pre className="text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-all bg-muted/40 rounded-xl px-4 py-3 text-foreground/80 overflow-auto max-h-56">
                  {result.output}
                </pre>
              </div>
            )}

            {/* Add server button */}
            {result.ok && (
              <div className="px-5 pb-5">
                <Button
                  onClick={saveServer}
                  disabled={saving}
                  variant="outline"
                  className="w-full h-9 rounded-xl gap-2 border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/30"
                >
                  {saving
                    ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                    : <RiAddLine className="w-3.5 h-3.5" />}
                  {saving ? "保存中…" : `添加服务器（.${normalizedTld}）`}
                </Button>
              </div>
            )}
          </div>
        )}

        {/* Info note about scrapers */}
        <div className="flex items-start gap-2 bg-sky-50/50 dark:bg-sky-950/20 border border-sky-200/50 dark:border-sky-800/30 rounded-xl px-4 py-3">
          <RiInformationLine className="w-4 h-4 text-sky-500 shrink-0 mt-0.5" />
          <p className="text-xs text-sky-700 dark:text-sky-400">
            <strong>注意：</strong>爬虫类型（Scraper）服务器无法通过此页面测试连通性，请直接在域名管理页面手动配置。本工具仅支持 TCP WHOIS 和 HTTP/RDAP 类型的实时连接验证。
          </p>
        </div>

      </div>
    </AdminLayout>
  );
}
