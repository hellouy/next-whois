import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const LOCK_FILES = [
  ".git/index.lock",
  ".git/MERGE_HEAD",
  ".git/MERGE_MODE",
  ".git/MERGE_MSG",
  ".git/CHERRY_PICK_HEAD",
  ".git/REVERT_HEAD",
];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const root = process.cwd();
  const results: Record<string, string> = {};

  for (const rel of LOCK_FILES) {
    const full = path.join(root, rel);
    if (!fs.existsSync(full)) {
      results[rel] = "not_found";
      continue;
    }

    // Try 1: direct unlink
    try {
      fs.unlinkSync(full);
      results[rel] = "deleted";
      continue;
    } catch (e1: any) {
      results[rel] = `unlink_failed:${e1.code}`;
    }

    // Try 2: shell rm via execSync
    try {
      execSync(`rm -f "${full}"`, { timeout: 3000 });
      if (!fs.existsSync(full)) {
        results[rel] = "deleted_via_shell";
        continue;
      }
    } catch { /* ignore */ }

    // Try 3: write empty string and rename out
    try {
      const tmp = path.join(root, ".git", "_unlock_tmp_" + Date.now());
      fs.writeFileSync(tmp, "");
      fs.renameSync(tmp, full + ".bak");
      results[rel] = "renamed_to_bak";
    } catch { /* ignore */ }
  }

  const deleted = Object.values(results).filter(v => v.startsWith("deleted")).length;
  const notFound = Object.values(results).filter(v => v === "not_found").length;

  return res.json({
    ok: deleted > 0 || notFound === LOCK_FILES.length,
    results,
    deleted,
    notFound,
  });
}
