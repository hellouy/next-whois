import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { run, one } from "@/lib/db-query";
import fs from "fs";
import path from "path";

const GITHUB_API = "https://api.github.com";
const SETTING_KEY = "github_token";
const SETTING_REPO_KEY = "github_repo";

async function getStoredToken(): Promise<string | null> {
  try {
    const row = await one<{ value: string }>(
      `SELECT value FROM site_settings WHERE key = $1`, [SETTING_KEY]
    );
    return row?.value ?? null;
  } catch {
    return null;
  }
}

async function getStoredRepo(): Promise<string | null> {
  try {
    const row = await one<{ value: string }>(
      `SELECT value FROM site_settings WHERE key = $1`, [SETTING_REPO_KEY]
    );
    return row?.value ?? null;
  } catch {
    return null;
  }
}

function getEnvToken(): string | null {
  return process.env.GITHUB_TOKEN ?? null;
}

async function resolveToken(): Promise<string | null> {
  return (await getStoredToken()) ?? getEnvToken() ?? null;
}

function parseOwnerRepo(input: string): { owner: string; repo: string } | null {
  const m = input.match(/(?:github\.com[:/])?([^/\s]+)\/([^\s/.]+?)(?:\.git)?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function resolveRepo(): Promise<{ owner: string; repo: string } | null> {
  const stored = await getStoredRepo();
  if (stored) {
    const parsed = parseOwnerRepo(stored);
    if (parsed) return parsed;
  }
  try {
    const cfg = fs.readFileSync(path.join(process.cwd(), ".git", "config"), "utf8");
    const m = cfg.match(/\[remote "origin"\][\s\S]*?url\s*=\s*([^\r\n]+)/);
    if (m) {
      const parsed = parseOwnerRepo(m[1].trim());
      if (parsed) return parsed;
    }
  } catch { /* ignore */ }
  return null;
}

async function ghFetch(endpoint: string, token: string, options?: RequestInit): Promise<any> {
  const res = await fetch(`${GITHUB_API}${endpoint}`, {
    ...options,
    headers: {
      Authorization: `token ${token}`,
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json?.message ?? `GitHub API error ${res.status}`);
  return json;
}

const IGNORE_DIRS = new Set([
  "node_modules", ".next", ".git", "dist", "build", ".vercel",
  "attached_assets", "__pycache__", ".cache",
]);
const IGNORE_EXTS = new Set([".lock", ".log"]);
const ALLOWED_DOTFILES = new Set([".gitignore", ".env.example", ".npmrc", ".replit"]);

function collectFiles(dir: string, root: string, out: string[] = []): string[] {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return out; }
  for (const e of entries) {
    if (IGNORE_DIRS.has(e.name)) continue;
    if (e.name.startsWith(".") && e.isDirectory()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      collectFiles(full, root, out);
    } else if (e.isFile()) {
      if (IGNORE_EXTS.has(path.extname(e.name))) continue;
      if (e.name.startsWith(".") && !ALLOWED_DOTFILES.has(e.name)) continue;
      out.push(path.relative(root, full).replace(/\\/g, "/"));
    }
  }
  return out;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { action, token: bodyToken, repo: bodyRepo } = req.body ?? {};

  if (action === "save_config") {
    try {
      if (bodyToken) {
        await run(
          `INSERT INTO site_settings (key, value, updated_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [SETTING_KEY, bodyToken.trim()]
        );
      }
      if (bodyRepo) {
        await run(
          `INSERT INTO site_settings (key, value, updated_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [SETTING_REPO_KEY, bodyRepo.trim()]
        );
      }
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (action === "status") {
    const token = await resolveToken();
    const repoInfo = await resolveRepo();
    const hasEnvToken = !!getEnvToken();
    const hasDbToken = !!(await getStoredToken());

    let latestSha: string | null = null;
    if (token && repoInfo) {
      try {
        const ref = await ghFetch(`/repos/${repoInfo.owner}/${repoInfo.repo}/git/ref/heads/main`, token);
        latestSha = (ref.object?.sha ?? "").slice(0, 12);
      } catch { /* ignore */ }
    }

    return res.json({
      ok: !!token,
      hasToken: !!token,
      hasEnvToken,
      hasDbToken,
      repo: repoInfo ? `${repoInfo.owner}/${repoInfo.repo}` : null,
      latestSha,
    });
  }

  if (action === "push") {
    const token = await resolveToken();
    if (!token) {
      return res.status(500).json({
        error: "未配置 GitHub Token。请在下方输入框填入后点击「保存配置」再重试。",
      });
    }

    const repoInfo = await resolveRepo();
    if (!repoInfo) {
      return res.status(500).json({
        error: "无法识别 GitHub 仓库地址，请在下方填入仓库（格式：owner/repo）后保存。",
      });
    }

    const { owner, repo } = repoInfo;
    const { message: commitMsg = "chore: sync from Replit admin" } = req.body ?? {};
    const root = process.cwd();

    try {
      const branchRef = await ghFetch(`/repos/${owner}/${repo}/git/ref/heads/main`, token);
      const headSha = branchRef.object.sha as string;
      const headCommit = await ghFetch(`/repos/${owner}/${repo}/git/commits/${headSha}`, token);
      const baseSha = headCommit.tree.sha as string;

      const files = collectFiles(root, root);
      const treeItems: { path: string; mode: string; type: string; sha: string }[] = [];
      let pushed = 0;
      let skipped = 0;

      for (const relPath of files) {
        const absPath = path.join(root, relPath);
        let buf: Buffer;
        try { buf = fs.readFileSync(absPath); }
        catch { skipped++; continue; }
        if (buf.length > 5 * 1024 * 1024) { skipped++; continue; }

        try {
          const blobRes = await ghFetch(`/repos/${owner}/${repo}/git/blobs`, token, {
            method: "POST",
            body: JSON.stringify({ content: buf.toString("base64"), encoding: "base64" }),
          });
          treeItems.push({ path: relPath, mode: "100644", type: "blob", sha: blobRes.sha });
          pushed++;
        } catch { skipped++; }
      }

      if (treeItems.length === 0) {
        return res.status(500).json({ error: "没有可推送的文件" });
      }

      const newTree = await ghFetch(`/repos/${owner}/${repo}/git/trees`, token, {
        method: "POST",
        body: JSON.stringify({ base_tree: baseSha, tree: treeItems }),
      });

      const newCommit = await ghFetch(`/repos/${owner}/${repo}/git/commits`, token, {
        method: "POST",
        body: JSON.stringify({ message: commitMsg, tree: newTree.sha, parents: [headSha] }),
      });

      await ghFetch(`/repos/${owner}/${repo}/git/refs/heads/main`, token, {
        method: "PATCH",
        body: JSON.stringify({ sha: newCommit.sha, force: false }),
      });

      return res.json({ ok: true, sha: (newCommit.sha as string).slice(0, 12), files: pushed, skipped });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(400).json({ error: "未知操作" });
}
