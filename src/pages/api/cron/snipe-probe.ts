/**
 * /api/cron/snipe-probe — domain-drop snipe probe trigger.
 *
 * Two modes (selected by ?mode=):
 *   daily (default) — Vercel cron (vercel.json), refreshes drop ETA + arming
 *                     precheck for every active target and probes each once.
 *   hunt             — GitHub Actions (.github/workflows/snipe-hunt.yml), only
 *                     targets inside their hunt window (drop_eta−1d … +2d).
 *                     The response contains only target ids + outcome enums —
 *                     domains never leave the server, keeping the public
 *                     workflow log sanitised.
 *
 * Auth mirrors /api/remind/process.ts: CRON_SECRET bearer/header OR an admin
 * session (allows on-demand triggering from the admin dashboard).
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { isAdminEmail } from "@/lib/admin-server";
import { runDailyProbe, runHuntProbe } from "@/lib/server/snipe-engine";

export const config = { maxDuration: 300 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Auth: accept CRON_SECRET (from Vercel cron / GitHub Actions) OR an admin
  // session (from the admin dashboard UI).
  const cronSecret = process.env.CRON_SECRET;
  let authed = false;
  if (cronSecret) {
    const authHeader = req.headers.authorization;
    const legacyHeader = req.headers["x-cron-secret"] as string | undefined;
    const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    if ((bearerToken || legacyHeader) === cronSecret) authed = true;
  }
  if (!authed) {
    const session = await getServerSession(req, res, authOptions);
    if (!session?.user?.email || !(await isAdminEmail(session.user.email))) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  const mode = req.query.mode === "hunt" ? "hunt" : "daily";

  try {
    const summary = mode === "hunt" ? await runHuntProbe() : await runDailyProbe();
    return res.status(200).json(summary);
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
}
