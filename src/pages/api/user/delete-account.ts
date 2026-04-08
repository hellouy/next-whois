import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, run, isDbReady } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { isAdminEmail } from "@/lib/admin-server";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "DELETE") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "请先登录" });

  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`delete-account:${ip}`, 3, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "操作过于频繁，请稍后再试" });

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  const email = session.user.email;

  // Guard against deleting the admin account — check both the env-var fallback
  // and the DB-backed admin email (which may differ from the env var).
  if (await isAdminEmail(email)) {
    return res.status(403).json({ error: "创始人账户无法删除" });
  }

  const { confirmEmail } = req.body as { confirmEmail?: string };
  if (!confirmEmail || confirmEmail.toLowerCase().trim() !== email.toLowerCase()) {
    return res.status(400).json({ error: "确认邮箱不匹配，请重新输入" });
  }

  try {
    const user = await one<{ id: string }>("SELECT id FROM users WHERE email = $1", [email]);
    if (!user) return res.status(404).json({ error: "用户不存在" });

    await run("DELETE FROM users WHERE id = $1", [user.id]);

    return res.status(200).json({ ok: true });
  } catch (err: any) {
    console.error("[delete-account]", err.message);
    return res.status(500).json({ error: "注销失败，请稍后重试" });
  }
}
