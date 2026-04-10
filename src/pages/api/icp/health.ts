import type { NextApiRequest, NextApiResponse } from "next";

export const config = { maxDuration: 10 };

export type IcpHealthResponse = {
  online: boolean;
  latencyMs: number | null;
  checkedAt: string;
  error?: string;
};

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<IcpHealthResponse>,
) {
  const checkedAt = new Date().toISOString();
  const t0 = Date.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const icpBase = (process.env.ICP_API_BASE ?? "http://api.ong:16181").replace(/\/$/, "");
    let upstream: Response;
    try {
      upstream = await fetch(
        `${icpBase}/query/web?search=miit.gov.cn&pageNum=1&pageSize=1`,
        {
          signal: controller.signal,
          headers: { Accept: "application/json", "User-Agent": "NextWhois/2.0" },
        },
      );
    } finally {
      clearTimeout(timer);
    }

    const latencyMs = Date.now() - t0;
    const contentType = upstream.headers.get("content-type") ?? "";
    const isJson = contentType.includes("json");

    if (!upstream.ok || !isJson) {
      res.setHeader("Cache-Control", "no-store");
      return res.status(200).json({
        online: false,
        latencyMs,
        checkedAt,
        error: `HTTP ${upstream.status}${!isJson ? "，非 JSON 响应" : ""}`,
      });
    }

    const data = await upstream.json();
    const online = data?.success === true || data?.code === 200;

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      online,
      latencyMs,
      checkedAt,
      error: online ? undefined : (data?.msg || "服务异常"),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "unknown";
    const latencyMs = Date.now() - t0;
    const isTimeout = msg.includes("abort") || msg.includes("timeout");
    const isNoConn = msg.includes("ENOTFOUND") || msg.includes("ECONNREFUSED") || msg.includes("fetch failed");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      online: false,
      latencyMs: isTimeout ? null : latencyMs,
      checkedAt,
      error: isTimeout ? "连接超时" : isNoConn ? "服务不可达" : msg.slice(0, 80),
    });
  }
}
