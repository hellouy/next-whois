import { useState } from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { RiGitBranchLine, RiLoader4Line, RiCheckLine, RiCloseLine, RiArrowUpLine, RiRefreshLine, RiEyeLine, RiEyeOffLine, RiInformationLine } from "@remixicon/react";

type Mode = "pull_push" | "force";

const MODES: { id: Mode; label: string; desc: string; accent: string; warn?: string }[] = [
  {
    id: "pull_push",
    label: "同步推送（推荐）",
    desc: "先拉取远程最新提交，合并后再推送。适合「远程有本地没有的提交」场景。",
    accent: "border-blue-500 bg-blue-500/10 text-blue-600 dark:text-blue-400",
  },
  {
    id: "force",
    label: "强制推送",
    desc: "用本地分支直接覆盖远程，忽略远程的提交。适合远程有无效提交或合并冲突时。",
    accent: "border-red-500 bg-red-500/10 text-red-600 dark:text-red-400",
    warn: "⚠ 强制推送会覆盖远程提交，请确认远程没有需要保留的内容。",
  },
];

export default function GitFixPage() {
  const [mode, setMode] = useState<Mode>("pull_push");
  const [log, setLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState<boolean | null>(null);
  const [customToken, setCustomToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const selected = MODES.find(m => m.id === mode)!;

  async function run() {
    setLoading(true);
    setLog([]);
    setDone(null);
    try {
      const body: Record<string, string> = { mode };
      if (customToken.trim().length >= 10) body.token = customToken.trim();

      const res = await fetch("/api/admin/git-force-push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setLog(data.log ?? []);
      setDone(data.success);
    } catch {
      setLog(["网络请求失败，请确认已登录管理员账号"]);
      setDone(false);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Head><title>Git 推送修复 — 管理后台</title></Head>
      <AdminLayout>
        <div className="max-w-xl mx-auto py-8 px-4 space-y-6">

          {/* Header */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
              <RiGitBranchLine className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-bold">Git 推送修复</h1>
              <p className="text-xs text-muted-foreground">解决 PUSH_REJECTED、index.lock、分支冲突等问题</p>
            </div>
          </div>

          {/* Env token notice */}
          <div className="glass-panel border border-emerald-300/50 dark:border-emerald-700/40 rounded-xl px-4 py-3 flex items-start gap-2.5">
            <RiInformationLine className="w-4 h-4 text-emerald-600 dark:text-emerald-400 mt-0.5 shrink-0" />
            <p className="text-xs text-emerald-700 dark:text-emerald-300 leading-relaxed">
              已检测到环境变量 <code className="font-mono bg-emerald-100 dark:bg-emerald-900/40 px-1 rounded">GITHUB_TOKEN</code>，无需手动输入 Token，点击下方按钮即可一键修复。
            </p>
          </div>

          {/* Mode selector */}
          <div className="space-y-3">
            <p className="text-sm font-semibold">操作模式</p>
            <div className="grid grid-cols-2 gap-3">
              {MODES.map(m => (
                <button
                  key={m.id}
                  onClick={() => setMode(m.id)}
                  className={cn(
                    "rounded-xl border-2 p-4 text-left transition-all",
                    mode === m.id ? m.accent : "border-border hover:border-border/80 bg-background"
                  )}
                >
                  <p className="text-sm font-semibold mb-1">{m.label}</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{m.desc}</p>
                </button>
              ))}
            </div>
            {selected.warn && (
              <div className="rounded-xl border border-red-300/60 dark:border-red-700/40 bg-red-50 dark:bg-red-950/20 px-4 py-2.5 text-xs text-red-700 dark:text-red-300">
                {selected.warn}
              </div>
            )}
          </div>

          {/* Advanced: custom token */}
          <div className="glass-panel border border-border rounded-xl overflow-hidden">
            <button
              onClick={() => setShowAdvanced(v => !v)}
              className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium hover:bg-muted/50 transition-colors"
            >
              <span className="flex items-center gap-2 text-muted-foreground">
                <RiEyeLine className="w-3.5 h-3.5" />
                自定义 Token（可选）
              </span>
              <span className={cn("text-xs text-muted-foreground transition-transform", showAdvanced ? "rotate-180" : "")}>▾</span>
            </button>
            {showAdvanced && (
              <div className="px-4 pb-4 pt-1 space-y-2 border-t border-border">
                <p className="text-xs text-muted-foreground">
                  留空则自动使用环境变量 GITHUB_TOKEN。仅在需要使用不同 Token 时填写。
                </p>
                <div className="relative">
                  <input
                    type={showToken ? "text" : "password"}
                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                    value={customToken}
                    onChange={e => setCustomToken(e.target.value)}
                    className="w-full border border-input bg-background rounded-xl px-3 py-2 pr-10 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showToken ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Action button */}
          <Button
            onClick={run}
            disabled={loading}
            size="lg"
            className={cn(
              "w-full h-12 rounded-xl text-base font-semibold gap-2 transition-all",
              mode === "force" ? "bg-red-600 hover:bg-red-700 text-white" : ""
            )}
          >
            {loading
              ? <><RiLoader4Line className="w-5 h-5 animate-spin" />执行中，请稍候…</>
              : mode === "pull_push"
                ? <><RiRefreshLine className="w-5 h-5" />一键同步并推送</>
                : <><RiArrowUpLine className="w-5 h-5" />一键强制推送</>
            }
          </Button>

          {/* Log output */}
          {(log.length > 0 || done !== null) && (
            <div className={cn(
              "glass-panel rounded-xl border overflow-hidden",
              done === true ? "border-emerald-300/60 dark:border-emerald-700/40"
              : done === false ? "border-red-300/60 dark:border-red-700/40"
              : "border-border"
            )}>
              <div className={cn(
                "px-4 py-2.5 flex items-center gap-2 text-sm font-semibold border-b",
                done === true ? "bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-300 border-emerald-300/40 dark:border-emerald-700/30"
                : done === false ? "bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-300 border-red-300/40 dark:border-red-700/30"
                : "bg-muted/50 text-muted-foreground border-border"
              )}>
                {done === true ? <RiCheckLine className="w-4 h-4" /> : done === false ? <RiCloseLine className="w-4 h-4" /> : <RiLoader4Line className="w-4 h-4 animate-spin" />}
                {done === true ? "操作成功" : done === false ? "操作失败" : "执行中…"}
              </div>
              <div className="px-4 py-3 space-y-0.5 font-mono text-xs">
                {log.map((line, i) => (
                  <p key={i} className={cn(
                    "py-0.5",
                    line.startsWith("✅") || line.startsWith("✓") ? "text-emerald-600 dark:text-emerald-400"
                    : line.startsWith("✗") || line.startsWith("❌") ? "text-red-600 dark:text-red-400"
                    : "text-muted-foreground"
                  )}>
                    {line}
                  </p>
                ))}
              </div>
            </div>
          )}

          {done === false && (
            <div className="glass-panel border border-amber-300/50 dark:border-amber-700/40 rounded-xl px-4 py-3 text-xs text-amber-700 dark:text-amber-300">
              <strong>提示：</strong>如果「同步推送」失败（合并冲突），可以切换到「强制推送」模式，用本地版本覆盖远程。
            </div>
          )}
        </div>
      </AdminLayout>
    </>
  );
}
