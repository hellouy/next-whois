import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import fs from "fs";
import path from "path";

const GITHUB_API = "https://api.github.com";

function getToken(): string | null {
  return process.env.GITHUB_TOKEN ?? null;
}

async function ghFetch(endpoint: string, options?: RequestInit): Promise<any> {
  const token = getToken();
  if (!token) throw new Error("GITHUB_TOKEN 未配置");
  const res = await fetch(`${GITHUB_API}${endpoint}`, {
    ...options,
    headers: {
      Authorization: `token ${token}`,
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json?.message ?? `GitHub API 错误 ${res.status}`);
  return json;
}

const IGNORE_DIRS = new Set([
  "node_modules", ".next", ".git", "dist", "build", ".vercel",
  "attached_assets", "__pycache__", ".cache",
]);

const IGNORE_EXTS = new Set([
  ".lock", ".log", ".DS_Store",
]);

function collectFiles(dir: string, root: string, out: string[] = []): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (IGNORE_DIRS.has(e.name)) continue;
    if (e.name.startsWith(".") && e.isDirectory()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      collectFiles(full, root, out);
    } else if (e.isFile()) {
      const ext = path.extname(e.name);
      if (IGNORE_EXTS.has(ext)) continue;
      if (e.name.startsWith(".") && [".gitignore", ".env.example", ".npmrc", ".replit"].indexOf(e.name) === -1) continue;
      out.push(path.relative(root, full).replace(/\\/g, "/"));
    }
  }
  return out;
}

async function createBlob(owner: string, repo: string, content: Buffer): Promise<string> {
  const res = await ghFetch(`/repos/${owner}/${repo}/git/blobs`, {
    method: "POST",
    body: JSON.stringify({
      content: content.toString("base64"),
      encoding: "base64",
    }),
  });
  return res.sha as string;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { action } = req.body ?? {};

  if (action === "status") {
    const token = getToken();
    if (!token) return res.json({ ok: false, error: "GITHUB_TOKEN 未配置" });

    const match = (process.env.GITHUB_REPO ?? "").match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
    const [owner, repo] = match ? [match[1], match[2]] : ["", ""];
    if (!owner) {
      const cfgPath = path.join(process.cwd(), ".git", "config");
      try {
        const cfg = fs.readFileSync(cfgPath, "utf8");
        const m = cfg.match(/url\s*=\s*.*github\.com[:/]([^/\s]+)\/([^\s.]+)/);
        if (m) {
          const [, o, r] = m;
          const branch = await ghFetch(`/repos/${o}/${r}/git/ref/heads/main`);
          return res.json({ ok: true, owner: o, repo: r, sha: (branch.object?.sha ?? "").slice(0, 12) });
        }
      } catch { /* ignore */ }
      return res.json({ ok: false, error: "无法读取 GitHub 仓库配置，请配置 GITHUB_REPO 环境变量" });
    }
    const branch = await ghFetch(`/repos/${owner}/${repo}/git/ref/heads/main`);
    return res.json({ ok: true, owner, repo, sha: (branch.object?.sha ?? "").slice(0, 12) });
  }

  if (action === "push") {
    const token = getToken();
    if (!token) return res.status(500).json({ error: "GITHUB_TOKEN 未配置" });

    const { message: commitMsg = "chore: sync from Replit" } = req.body ?? {};

    let owner = "";
    let repo = "";

    const envRepo = process.env.GITHUB_REPO ?? "";
    const envMatch = envRepo.match(/github\.com[:/]([^/\s]+)\/([^\s.]+?)(?:\.git)?$/);
    if (envMatch) {
      [, owner, repo] = envMatch;
    } else {
      try {
        const cfg = fs.readFileSync(path.join(process.cwd(), ".git", "config"), "utf8");
        const m = cfg.match(/url\s*=\s*.*github\.com[:/]([^/\s]+)\/([^\s.]+?)(?:\.git)?[\s\r\n]/);
        if (m) { [, owner, repo] = m; }
      } catch { /* ignore */ }
    }

    if (!owner || !repo) {
      return res.status(500).json({
        error: "无法确定 GitHub 仓库，请在环境变量中配置 GITHUB_REPO=https://github.com/owner/repo",
      });
    }

    const root = process.cwd();

    const branchRef = await ghFetch(`/repos/${owner}/${repo}/git/ref/heads/main`);
    const headSha = branchRef.object.sha as string;
    const headCommit = await ghFetch(`/repos/${owner}/${repo}/git/commits/${headSha}`);
    const baseSha = headCommit.tree.sha as string;

    const files = collectFiles(root, root);

    const treeItems: { path: string; mode: string; type: string; sha: string }[] = [];
    let pushed = 0;
    let skipped = 0;

    for (const relPath of files) {
      const absPath = path.join(root, relPath);
      let buf: Buffer;
      try {
        buf = fs.readFileSync(absPath);
      } catch {
        skipped++;
        continue;
      }
      if (buf.length > 10 * 1024 * 1024) { skipped++; continue; }

      try {
        const sha = await createBlob(owner, repo, buf);
        treeItems.push({ path: relPath, mode: "100644", type: "blob", sha });
        pushed++;
      } catch {
        skipped++;
      }
    }

    if (treeItems.length === 0) {
      return res.status(500).json({ error: "没有可推送的文件" });
    }

    const newTree = await ghFetch(`/repos/${owner}/${repo}/git/trees`, {
      method: "POST",
      body: JSON.stringify({ base_tree: baseSha, tree: treeItems }),
    });

    const newCommit = await ghFetch(`/repos/${owner}/${repo}/git/commits`, {
      method: "POST",
      body: JSON.stringify({
        message: commitMsg,
        tree: newTree.sha,
        parents: [headSha],
      }),
    });

    await ghFetch(`/repos/${owner}/${repo}/git/refs/heads/main`, {
      method: "PATCH",
      body: JSON.stringify({ sha: newCommit.sha, force: false }),
    });

    return res.json({
      ok: true,
      sha: (newCommit.sha as string).slice(0, 12),
      files: pushed,
      skipped,
    });
  }

  return res.status(400).json({ error: "未知操作" });
}
