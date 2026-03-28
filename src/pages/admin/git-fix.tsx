import { useState } from "react";
import Head from "next/head";

type Mode = "pull_push" | "force";

const MODES: { id: Mode; label: string; desc: string; color: string; warn?: string }[] = [
  {
    id: "pull_push",
    label: "同步推送（推荐）",
    desc: "先拉取远程最新提交，合并后再推送。适合「远程有本地没有的提交」场景。",
    color: "#2563eb",
  },
  {
    id: "force",
    label: "强制推送",
    desc: "用本地分支直接覆盖远程，忽略远程的提交。适合远程有无效提交、或合并冲突无法解决时。",
    color: "#dc2626",
    warn: "⚠ 强制推送会覆盖远程提交，请确认远程没有需要保留的内容！",
  },
];

export default function GitFix() {
  const [token, setToken] = useState("");
  const [mode, setMode] = useState<Mode>("pull_push");
  const [log, setLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState<boolean | null>(null);
  const [showToken, setShowToken] = useState(false);

  async function run() {
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
    <>
      <Head>
        <title>Git 修复 — 管理后台</title>
      </Head>
      <div style={{ maxWidth: 520, margin: "40px auto", padding: "0 20px", fontFamily: "system-ui, sans-serif", fontSize: 14 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Git 推送修复工具</h2>
        <p style={{ color: "#6b7280", marginBottom: 24 }}>
          解决 PUSH_REJECTED、index.lock、分支冲突等问题。<br />
          仅在 Replit 开发环境可用（Vercel 无 .git 目录）。
        </p>

        {/* ── Mode selector ── */}
        <div style={{ marginBottom: 20 }}>
          <label style={{ display: "block", fontWeight: 600, marginBottom: 10, color: "#374151" }}>
            操作模式
          </label>
          <div style={{ display: "flex", gap: 10 }}>
            {MODES.map((m) => (
              <button
                key={m.id}
                onClick={() => setMode(m.id)}
                style={{
                  flex: 1,
                  padding: "12px 10px",
                  borderRadius: 10,
                  border: `2px solid ${mode === m.id ? m.color : "#e5e7eb"}`,
                  background: mode === m.id ? `${m.color}10` : "#fff",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.15s",
                }}
              >
                <div style={{ fontWeight: 700, color: mode === m.id ? m.color : "#374151", marginBottom: 4 }}>
                  {m.label}
                </div>
                <div style={{ fontSize: 12, color: "#6b7280", lineHeight: 1.5 }}>{m.desc}</div>
              </button>
            ))}
          </div>
          {selectedMode.warn && (
            <div style={{ marginTop: 10, padding: "10px 14px", background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 8, color: "#991b1b", fontSize: 13 }}>
              {selectedMode.warn}
            </div>
          )}
        </div>

        {/* ── Token input ── */}
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: "block", fontWeight: 600, marginBottom: 6, color: "#374151" }}>
            GitHub Personal Access Token
          </label>
          <div style={{ position: "relative" }}>
            <input
              type={showToken ? "text" : "password"}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              style={{
                width: "100%",
                boxSizing: "border-box",
                border: "1px solid #d1d5db",
                borderRadius: 8,
                padding: "10px 44px 10px 12px",
                fontSize: 14,
                fontFamily: "monospace",
                background: "#fff",
              }}
            />
            <button
              onClick={() => setShowToken((v) => !v)}
              style={{
                position: "absolute",
                right: 12,
                top: "50%",
                transform: "translateY(-50%)",
                background: "none",
                border: "none",
                cursor: "pointer",
                color: "#9ca3af",
                fontSize: 12,
              }}
            >
              {showToken ? "隐藏" : "显示"}
            </button>
          </div>
          <p style={{ fontSize: 12, color: "#6b7280", marginTop: 8, lineHeight: 1.6 }}>
            GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)<br />
            → Generate new token，勾选 <strong>repo</strong> 权限。Token 不会被储存。
          </p>
        </div>

        {/* ── Submit button ── */}
        <button
          onClick={run}
          disabled={loading || !token.trim()}
          style={{
            width: "100%",
            background: loading || !token.trim() ? "#9ca3af" : selectedMode.color,
            color: "#fff",
            border: "none",
            borderRadius: 10,
            padding: "14px 32px",
            fontSize: 16,
            fontWeight: "bold",
            cursor: loading || !token.trim() ? "not-allowed" : "pointer",
            marginBottom: 20,
            transition: "background 0.15s",
          }}
        >
          {loading
            ? "执行中，请稍候…"
            : mode === "pull_push"
              ? "🔄 同步并推送"
              : "⚡ 强制推送"}
        </button>

        {/* ── Log output ── */}
        {(log.length > 0 || done !== null) && (
          <div
            style={{
              background: done ? "#f0fdf4" : done === false ? "#fef2f2" : "#f9fafb",
              border: `1px solid ${done ? "#86efac" : done === false ? "#fca5a5" : "#e5e7eb"}`,
              borderRadius: 12,
              padding: "16px 18px",
            }}
          >
            <p style={{ fontWeight: 700, marginBottom: 10, color: done ? "#166534" : done === false ? "#991b1b" : "#374151" }}>
              {done ? "✅ 操作成功！" : done === false ? "❌ 操作失败" : "⏳ 执行中…"}
            </p>
            <div style={{ fontFamily: "monospace", fontSize: 13 }}>
              {log.map((line, i) => (
                <div
                  key={i}
                  style={{
                    padding: "2px 0",
                    color: line.startsWith("✗") || line.startsWith("❌")
                      ? "#991b1b"
                      : line.startsWith("✅") || line.startsWith("✓")
                        ? "#166534"
                        : "#374151",
                    borderBottom: i < log.length - 1 ? "1px solid #0000000a" : "none",
                  }}
                >
                  {line}
                </div>
              ))}
            </div>
          </div>
        )}

        {done === false && (
          <div style={{ marginTop: 16, padding: "12px 16px", background: "#fffbeb", border: "1px solid #fde68a", borderRadius: 10, fontSize: 13, color: "#92400e" }}>
            <strong>提示：</strong>如果「同步推送」失败（合并冲突），可以切换到「强制推送」模式用本地版本覆盖远程。
          </div>
        )}
      </div>
    </>
  );
}
