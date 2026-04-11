import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { setTldApiSource, getTldApiSource } from "@/lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    const { tld } = req.query;
    if (!tld || typeof tld !== "string") return res.status(400).json({ error: "tld required" });
    const src = await getTldApiSource(tld.trim().toLowerCase().replace(/^\./, ""));
    return res.json({ tld, source: src });
  }

  if (req.method === "POST") {
    const { tld, source } = req.body as { tld?: string; source?: string | null };
    if (!tld) return res.status(400).json({ error: "tld required" });
    const cleanTld = tld.trim().toLowerCase().replace(/^\./, "");
    const cleanSource = source && ["tianhu", "yisi"].includes(source) ? source : null;
    await setTldApiSource(cleanTld, cleanSource);
    return res.json({ ok: true, tld: cleanTld, source: cleanSource });
  }

  return res.status(405).end();
}
