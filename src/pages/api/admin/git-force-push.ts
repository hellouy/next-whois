import { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { spawnSync } from "child_process";
import fs from "fs";
import path from "path";

type Mode = "pull_push" | "force";

function runCmd(
  cmd: string,
  args: string[],
  cwd: string,
  env?: NodeJS.ProcessEnv,
): { out: string; err: string; ok: boolean; code: number | null } {
  const r = spawnSync(cmd, args, {
    cwd,
    timeout: 60_000,
    encoding: "utf8",
    env: env ?? { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  });
  return {
    out: (r.stdout ?? "").trim(),
    err: (r.stderr ?? "").trim(),
    ok: r.status === 0,
    code: r.status,
  };
}

function sanitize(text: string, token: string, authUrl: string, rawUrl: string): string {
  return text
    .replace(new RegExp(token.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), "***")
    .replace(new RegExp(authUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), rawUrl);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // Internal bypass: when called with X-Push-Secret matching GITHUB_TOKEN env var,
  // skip session auth so the agent can trigger pushes without a browser session.
  const pushSecret = req.headers["x-push-secret"] as string | undefined;
  const envToken = process.env.GITHUB_TOKEN;
  const internalAuth = !!(pushSecret && envToken && pushSecret === envToken);

  if (!internalAuth) {
    const session = await requireAdmin(req, res);
    if (!session) return;
  }

  if (process.env.VERCEL) {
    return res.status(400).json({
      success: false,
      log: [
        "✗ 此功能仅在本地 / Replit 开发环境可用",
        "  Vercel 部署为只读文件系统，不含 .git 目录",
        "  请在 Replit 开发环境中执行 Git 操作",
      ],
    });
  }

  const { token: bodyToken, mode = "force" } = req.body as { token?: string; mode?: Mode };
  // When called internally (internalAuth=true), fall back to GITHUB_TOKEN env var
  const token = bodyToken || (internalAuth ? process.env.GITHUB_TOKEN : undefined);
  if (!token || token.trim().length < 10) {
    return res.status(400).json({ success: false, log: ["✗ 请提供 GitHub Personal Access Token（至少10位）"] });
  }

  const cwd = process.cwd();
  const log: string[] = [];

  // ── Step 1: Remove stale index.lock ───────────────────────────────────────
  const lockFile = path.join(cwd, ".git", "index.lock");
  if (fs.existsSync(lockFile)) {
    try {
      fs.unlinkSync(lockFile);
      log.push("✓ 已删除 stale index.lock");
    } catch (e) {
      log.push(`✗ 删除锁文件失败: ${e}`);
    }
  } else {
    log.push("  无 index.lock（状态正常）");
  }

  // ── Step 2: Check current branch ──────────────────────────────────────────
  const branch = runCmd("git", ["rev-parse", "--abbrev-ref", "HEAD"], cwd);
  const currentBranch = branch.out || "main";
  log.push(`  当前分支: ${currentBranch}`);

  // ── Step 3: Get remote URL ────────────────────────────────────────────────
  const remoteUrl = runCmd("git", ["config", "--get", "remote.origin.url"], cwd);
  const rawUrl = remoteUrl.out || "";
  if (!rawUrl) {
    log.push("✗ 未找到 remote.origin.url — 请确认已设置 GitHub Remote");
    return res.json({ success: false, log });
  }

  // Build authenticated URL
  const authUrl = rawUrl.startsWith("https://github.com/")
    ? rawUrl.replace("https://github.com/", `https://${token.trim()}@github.com/`)
    : rawUrl;
  log.push("✓ 已注入 GitHub Token");

  const sanitizeLogs = (text: string) => sanitize(text, token, authUrl, rawUrl);

  // ── Mode: pull_push — fetch → merge → push ────────────────────────────────
  if (mode === "pull_push") {
    // Abort any pending operations
    runCmd("git", ["merge", "--abort"], cwd);
    runCmd("git", ["rebase", "--abort"], cwd);

    // Fetch latest remote state
    const fetch = runCmd("git", ["fetch", authUrl, `refs/heads/${currentBranch}:refs/remotes/origin/${currentBranch}`], cwd, {
      ...process.env,
      GIT_TERMINAL_PROMPT: "0",
    });
    if (fetch.ok) {
      log.push("✓ Fetch 远程成功");
    } else {
      log.push(`✗ Fetch 失败: ${sanitizeLogs(fetch.err || fetch.out)}`);
      return res.json({ success: false, log });
    }

    // Check if there's a divergence
    const aheadBehind = runCmd("git", ["rev-list", "--left-right", "--count", `HEAD...origin/${currentBranch}`], cwd);
    if (aheadBehind.ok) {
      const [ahead = "0", behind = "0"] = aheadBehind.out.split("\t");
      log.push(`  本地领先远程: ${ahead} 个提交，落后: ${behind} 个提交`);
    }

    // Merge remote changes
    const merge = runCmd("git", ["merge", `origin/${currentBranch}`, "--no-edit", "-m", "Merge remote changes"], cwd);
    if (merge.ok) {
      log.push("✓ 合并远程提交成功");
    } else {
      const mergeMsg = sanitizeLogs(merge.err || merge.out);
      if (mergeMsg.includes("CONFLICT") || mergeMsg.includes("conflict")) {
        log.push(`✗ 合并冲突，请手动解决: ${mergeMsg.split("\n")[0]}`);
        log.push("  建议改用「强制推送」模式覆盖远程，或手动解决冲突后重试");
      } else if (mergeMsg.includes("Already up to date") || mergeMsg.includes("already up-to-date")) {
        log.push("  本地已是最新，无需合并");
      } else {
        log.push(`✗ 合并失败: ${mergeMsg}`);
        return res.json({ success: false, log });
      }
    }

    // Push (normal, non-force)
    const push = runCmd("git", ["push", authUrl, `HEAD:${currentBranch}`], cwd, {
      ...process.env,
      GIT_TERMINAL_PROMPT: "0",
    });

    if (push.ok) {
      log.push("✅ Push 成功！远程已更新。");
      return res.json({ success: true, log });
    } else {
      const pushMsg = sanitizeLogs(push.err || push.out);
      log.push(`✗ Push 失败: ${pushMsg}`);
      if (pushMsg.includes("rejected") || pushMsg.includes("PUSH_REJECTED")) {
        log.push("  提示：远程仍有未同步提交。请改用「强制推送」模式，或手动解决后重试。");
      }
      return res.json({ success: false, log });
    }
  }

  // ── Mode: force — force push overwriting remote ───────────────────────────
  // Abort any pending operations first
  const abort = runCmd("git", ["merge", "--abort"], cwd);
  log.push(abort.ok ? "✓ 已中止待定合并" : "  无待定合并");
  const rebaseAbort = runCmd("git", ["rebase", "--abort"], cwd);
  if (rebaseAbort.ok) log.push("✓ 已中止待定 rebase");

  // Show what we're about to push
  const logHead = runCmd("git", ["log", "--oneline", "-3"], cwd);
  if (logHead.ok) {
    log.push("  最近3次提交:");
    for (const line of logHead.out.split("\n").slice(0, 3)) {
      log.push(`    ${line}`);
    }
  }

  const push = runCmd(
    "git",
    ["push", authUrl, `HEAD:${currentBranch}`, "--force"],
    cwd,
    { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  );

  if (push.ok) {
    log.push("✅ Force Push 成功！GitHub 已强制更新。");
    return res.json({ success: true, log });
  } else {
    const errMsg = sanitizeLogs(push.err || push.out || "未知错误");
    log.push(`✗ Force Push 失败: ${errMsg}`);
    return res.json({ success: false, log });
  }
}
