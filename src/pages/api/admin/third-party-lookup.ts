import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { many } from "@/lib/db-query";

const TIMEOUT = 12000;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await requireAdmin(req, res);
  if (!session) return;

  const { tld, service } = req.body as { tld?: string; service?: string };
  if (!tld || !service) return res.status(400).json({ ok: false, error: "tld and service are required" });

  const cleanTld = tld.trim().toLowerCase().replace(/^\./, "");
  const domain = `example.${cleanTld}`;

  try {
    if (service === "nazhumi") {
      const r = await fetch(
        `https://www.nazhumi.com/api/v1?domain=${encodeURIComponent(cleanTld)}&order=new`,
        { signal: AbortSignal.timeout(TIMEOUT), headers: { Accept: "application/json" } },
      );
      if (!r.ok) return res.json({ ok: false, error: `HTTP ${r.status}` });
      const j = await r.json();
      const count = j.data?.price?.length ?? 0;
      return res.json({
        ok: count > 0,
        details: count > 0 ? `已获取 .${cleanTld} 的 ${count} 条注册商价格数据` : `暂无 .${cleanTld} 数据`,
        raw: JSON.stringify(j).slice(0, 800),
      });
    }

    if (service === "miqingju") {
      const r = await fetch(
        `https://api.miqingju.com/api/v1/query?tld=${encodeURIComponent(cleanTld)}`,
        { signal: AbortSignal.timeout(TIMEOUT), headers: { Accept: "application/json" } },
      );
      if (!r.ok) return res.json({ ok: false, error: `HTTP ${r.status}` });
      const j = await r.json();
      const count = j.data?.length ?? 0;
      return res.json({
        ok: !!j.success,
        details: j.success
          ? `已获取 .${cleanTld} 的 ${count} 条注册商价格数据`
          : (j.message ?? `暂无 .${cleanTld} 数据`),
        raw: JSON.stringify(j).slice(0, 800),
      });
    }

    if (service === "tianhu") {
      const r = await fetch(
        `https://api.tian.hu/whois/${encodeURIComponent(domain)}`,
        { signal: AbortSignal.timeout(TIMEOUT), headers: { Accept: "application/json" } },
      );
      if (!r.ok) return res.json({ ok: false, error: `HTTP ${r.status}` });
      const j = await r.json();
      if (j.code !== 200) return res.json({ ok: false, error: j.message || "查询失败", raw: JSON.stringify(j).slice(0, 400) });
      const d = j.data?.formatted;
      return res.json({
        ok: true,
        details: `${domain} · 注册商: ${d?.registrar?.registrar_name ?? "已返回数据"} · NS: ${(d?.domain?.name_servers ?? []).length} 条`,
        raw: JSON.stringify(j).slice(0, 800),
      });
    }

    if (service === "yisi") {
      const rows = await many<{ value: string }>(
        "SELECT value FROM site_settings WHERE key = 'api_yisi_key'",
      );
      const apiKey = rows[0]?.value || process.env.YISI_API_KEY || "";
      if (!apiKey) return res.json({ ok: false, error: "亿思云未配置 API Key" });
      const r = await fetch(
        `https://yisi.yun/api/lookup?query=${encodeURIComponent(domain)}`,
        { signal: AbortSignal.timeout(TIMEOUT), headers: { Accept: "application/json", "x-api-key": apiKey } },
      );
      const j = await r.json();
      if (!j.status) return res.json({ ok: false, error: j.error || "查询失败", raw: JSON.stringify(j).slice(0, 400) });
      return res.json({
        ok: true,
        details: `${j.result?.domain ?? domain} · 注册商: ${j.result?.registrar ?? "已返回数据"}`,
        raw: JSON.stringify(j).slice(0, 800),
      });
    }

    return res.status(400).json({ ok: false, error: `未知服务: ${service}` });
  } catch (e: any) {
    return res.json({ ok: false, error: e.message || "请求失败" });
  }
}
