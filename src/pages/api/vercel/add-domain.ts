import type { NextApiRequest, NextApiResponse } from "next";
import { one, run, isDbReady } from "@/lib/db-query";

export const config = { maxDuration: 15 };

const VERCEL_API = "https://api.vercel.com";

function headers() {
  return {
    Authorization: `Bearer ${process.env.VERCEL_API_TOKEN}`,
    "Content-Type": "application/json",
  };
}

function projectUrl(path = "") {
  const base = `${VERCEL_API}/v10/projects/${process.env.VERCEL_PROJECT_ID}/domains`;
  return path ? `${base}${path}` : base;
}

async function getDomainInfo(domain: string) {
  const res = await fetch(
    `${VERCEL_API}/v9/projects/${process.env.VERCEL_PROJECT_ID}/domains/${domain}`,
    { headers: headers() },
  );
  return res.ok ? res.json() : null;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { domain, stampId } = req.body;
  if (!domain || !stampId)
    return res.status(400).json({ error: "Missing domain or stampId" });

  if (!process.env.VERCEL_API_TOKEN || !process.env.VERCEL_PROJECT_ID)
    return res.status(503).json({ error: "Vercel integration not configured" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const stamp = await one<{ id: string; verified: boolean }>(
    "SELECT id, verified FROM stamps WHERE id = $1 AND domain = $2",
    [stampId, String(domain).toLowerCase().trim()],
  );
  if (!stamp) return res.status(404).json({ error: "Stamp not found" });
  if (stamp.verified) return res.status(200).json({ verified: true, already: true });

  const markVerified = () =>
    run(
      "UPDATE stamps SET verified = true, verified_at = $1 WHERE id = $2",
      [new Date().toISOString(), stampId],
    );

  const addRes = await fetch(projectUrl(), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ name: domain }),
  });
  const addData = await addRes.json();

  if (!addRes.ok) {
    const code: string = addData.error?.code ?? "";
    if (code === "domain_already_exists" || addRes.status === 409) {
      const info = await getDomainInfo(domain);
      if (info) {
        if (info.verified) {
          await markVerified();
          return res.status(200).json({ verified: true });
        }
        const txt = (info.verification ?? []).find((v: any) => v.type === "TXT");
        return res.status(200).json({
          verified: false,
          txtName: "_vercel",
          txtValue: txt?.value ?? null,
          txtFullDomain: txt?.domain ?? `_vercel.${domain}`,
        });
      }
    }
    return res.status(200).json({
      verified: false,
      apiError: addData.error?.message ?? "Failed to register domain with Vercel",
      apiCode: code,
    });
  }

  if (addData.verified) {
    await markVerified();
    return res.status(200).json({ verified: true });
  }

  const txt = (addData.verification ?? []).find((v: any) => v.type === "TXT");
  return res.status(200).json({
    verified: false,
    txtName: "_vercel",
    txtValue: txt?.value ?? null,
    txtFullDomain: txt?.domain ?? `_vercel.${domain}`,
  });
}
