import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import {
  RiGitBranchLine, RiLoader4Line, RiCheckboxCircleLine,
  RiCloseCircleLine, RiEyeLine, RiEyeOffLine,
  RiArrowUpCircleLine, RiFlashlightLine,
} from "@remixicon/react";
type Mode = "pull_push" | "force";

const MODES: { id: Mode; label: string; desc: string; warn?: string }[] = [
  {
    id: "pull_push",
    label: "同步推送（推荐）",
    desc: "先拉取远程最新提交，合并后再推送。适合「远程有本地没有的提交」场景。",
  },
  {
    id: "force",
    label: "强制推送",
    desc: "用本地分支直接覆盖远程，忽略远程的提交。适合远程有无效提交、或合并冲突无法解决时。",
    warn: "强制推送会覆盖远程提交，请确认远程没有需要保留的内容！",
  },
];

export default function GitFix() {
  const [token, setToken] = React.useState("");
  const [mode, setMode] = React.useState<Mode>("pull_push");
  const [log, setLog] = React.useState<string[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [done, setDone] = React.useState<boolean | null>(null);
  const [showToken, setShowToken] = React.useState(false);

  async function runPush() {
    if (!token.trim()) return;
    setLoading(true);
    setLog([]);
    setDone(null);
    try {
      const res = await fetch("/api/admin/git-force-push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, mode }),
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

  const selectedMode = MODES.find((m) => m.id === mode)!;

  return (
    <AdminLayout>
      <div className="max-w-xl space-y-6">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <RiGitBranchLine className="w-5 h-5 text-primary" />
            Git 推送修复工具
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            解决 PUSH_REJECTED、index.lock、分支冲突等问题。<br />
            仅在 Replit 开发环境可用（Vercel 无 .git 目录）。
          </p>
        </div>

        {/* Mode selector */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">操作模式</Label>
          <div className="grid grid-cols-2 gap-3">
            {MODES.map(m => (
              <button
                key={m.id}
                type="button"
                onClick={() => setMode(m.id)}
                className={cn(
                  "rounded-xl border-2 p-3 text-left transition-colors",
                  mode === m.id
                    ? m.id === "force"
                      ? "border-red-500 bg-red-50 dark:bg-red-950/30"
                      : "border-primary bg-primary/5"
                    : "border-border bg-muted/20 hover:bg-muted/40"
                )}
              >
                <div className={cn(
                  "text-sm font-semibold mb-1 flex items-center gap-1",
                  mode === m.id
                    ? m.id === "force" ? "text-red-600" : "text-primary"
                    : "text-foreground"
                )}>
                  {m.id === "force"
                    ? <RiFlashlightLine className="w-3.5 h-3.5" />
                    : <RiArrowUpCircleLine className="w-3.5 h-3.5" />}
                  {m.label}
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed">{m.desc}</p>
              </button>
            ))}
          </div>
          {selectedMode.warn && (
            <div className="rounded-xl border border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-950/30 px-3 py-2.5 text-sm text-orange-700 dark:text-orange-400">
              ⚠ {selectedMode.warn}
            </div>
          )}
        </div>

        {/* Token input */}
        <div className="space-y-2">
          <Label className="text-sm font-medium">GitHub Personal Access Token</Label>
          <div className="relative">
            <Input
              type={showToken ? "text" : "password"}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
              value={token}
              onChange={e => setToken(e.target.value)}
              onKeyDown={e => e.key === "Enter" && runPush()}
              className="h-10 pr-10 font-mono text-sm"
            />
            <button
              type="button"
              onClick={() => setShowToken(v => !v)}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              {showToken
                ? <RiEyeOffLine className="w-4 h-4" />
                : <RiEyeLine className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            Token 需有 <code className="bg-muted px-1 rounded">repo</code> 权限。仅传输到本机 API，不存储。
          </p>
        </div>

        <Button
          onClick={runPush}
          disabled={loading || !token.trim()}
          className={cn("w-full h-10", mode === "force" && "bg-red-600 hover:bg-red-700")}
        >
          {loading
            ? <><RiLoader4Line className="w-4 h-4 animate-spin mr-2" />执行中，请稍候…</>
            : mode === "pull_push"
              ? <><RiArrowUpCircleLine className="w-4 h-4 mr-2" />同步并推送</>
              : <><RiFlashlightLine className="w-4 h-4 mr-2" />强制推送</>}
        </Button>

        {/* Log output */}
        {(log.length > 0 || done !== null) && (
          <div className={cn(
            "rounded-xl border p-4 space-y-3",
            done === true  && "border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/30",
            done === false && "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/30",
            done === null  && "border-border bg-muted/20",
          )}>
            <div className={cn(
              "flex items-center gap-2 text-sm font-semibold",
              done === true  && "text-emerald-700 dark:text-emerald-400",
              done === false && "text-red-700 dark:text-red-400",
              done === null  && "text-foreground",
            )}>
              {done === true  && <RiCheckboxCircleLine className="w-4 h-4" />}
              {done === false && <RiCloseCircleLine className="w-4 h-4" />}
              {done === true ? "操作成功！" : done === false ? "操作失败" : "执行中…"}
            </div>
            <div className="font-mono text-xs space-y-0.5 max-h-64 overflow-y-auto">
              {log.map((line, i) => (
                <div key={i} className={cn(
                  "py-0.5",
                  (line.startsWith("✗") || line.startsWith("❌")) && "text-red-600 dark:text-red-400",
                  (line.startsWith("✅") || line.startsWith("✓")) && "text-emerald-600 dark:text-emerald-400",
                  !(line.startsWith("✗") || line.startsWith("❌") || line.startsWith("✅") || line.startsWith("✓")) && "text-muted-foreground",
                )}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        )}

        {done === false && (
          <div className="rounded-xl border border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-950/30 px-3 py-2.5 text-sm text-yellow-800 dark:text-yellow-400">
            <strong>提示：</strong>如果「同步推送」失败（合并冲突），可以切换到「强制推送」模式用本地版本覆盖远程。
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
