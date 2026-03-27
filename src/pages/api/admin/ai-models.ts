import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getProvidersInfoAsync } from "@/lib/server/ai-providers";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const session = await requireAdmin(req, res);
  if (!session) return;

  const providers = await getProvidersInfoAsync();
  const configured = providers.filter(p => p.configured);
  return res.json({
    providers,
    configured_count: configured.length,
    primary: configured[0] ?? null,
  });
}
