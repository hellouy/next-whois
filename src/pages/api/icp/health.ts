import type { NextApiRequest, NextApiResponse } from "next";
import { getRedisValue, setRedisValue } from "@/lib/server/redis";

export const config = { maxDuration: 12 };

export type IcpHealthResponse = {
  online: boolean;
  latencyMs: number | null;
  checkedAt: string;
  source?: "miit" | "icpq";
  error?: string;
};

const MIIT_AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth";
const CACHE_KEY = "icp:health:status";
const CACHE_TTL = 300; // 5 minutes — ICP 查询服务状态极少变化
const ICP_BASE = (process.env.ICP_API_BASE ?? "https://icp.ng").replace(/\/$/, "");

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<IcpHealthResponse>,
) {
  res.setHeader("Cache-Control", "no-store");
  const refresh = req.query.refresh === "1";

  // ── L2 Redis cache ────────────────────────────────────────────────────────
  if (!refresh) {
    try {
      const cached = await getRedisValue(CACHE_KEY);
      if (cached) {
        res.setHeader("X-Cache", "HIT");
        return res.status(200).json(JSON.parse(cached));
      }
    } catch {
      // Redis unavailable → fall through to live check
    }
  }

  const checkedAt = new Date().toISOString();

  // ── Check ICP_Query service (primary source: icp.ng) ──────────────────────
  const t0 = Date.now();
  let icpOnline = false;
  let icpLatency: number | null = null;
  let icpErr = "不可用";
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    let icpRes: Response;
    try {
      icpRes = await fetch(
        `${ICP_BASE}/query/web?search=miit.gov.cn&pageNum=1&pageSize=1`,
        {
          signal: controller.signal,
          headers: { Accept: "application/json", "User-Agent": "NextWhois/3.0" },
        },
      );
    } finally {
      clearTimeout(timer);
    }
    icpLatency = Date.now() - t0;
    const icpData = await icpRes.json().catch(() => null);
    icpOnline = icpData?.success === true || icpData?.code === 200;
    if (!icpOnline) icpErr = String(icpData?.msg || icpData?.message || `HTTP ${icpRes.status}`);

    if (icpOnline) {
      const payload: IcpHealthResponse = { online: true, latencyMs: icpLatency, checkedAt, source: "icpq" };
      void cacheResult(payload);
      return res.status(200).json(payload);
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "unknown";
    icpErr = msg.includes("abort") || msg.includes("timeout") ? "连接超时" : msg.slice(0, 60);
  }

  // ── Check MIIT direct access (fallback source) ────────────────────────────
  const t1 = Date.now();
  let miitLatency: number | null = null;
  let miitErr = "不可用";
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const body = JSON.stringify({ authKey: "healthcheck", timeStamp: Date.now() });
    let authRes: Response;
    try {
      authRes = await fetch(MIIT_AUTH_URL, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
          "Origin": "https://beian.miit.gov.cn",
          "Referer": "https://beian.miit.gov.cn/",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          "Accept": "application/json",
        },
        body,
      });
    } finally {
      clearTimeout(timer);
    }
    miitLatency = Date.now() - t1;
    const data = await authRes.json().catch(() => null);
    const miitOnline = data?.success === true || data?.code === 200;

    if (miitOnline) {
      const payload: IcpHealthResponse = { online: true, latencyMs: miitLatency, checkedAt, source: "miit" };
      void cacheResult(payload);
      return res.status(200).json(payload);
    }

    // code 500 = MIIT server error (service down); definite non-500 errors get
    // reported straight away since the fallback is clearly broken too.
    if (data?.code !== 500 && data?.code !== undefined) {
      const payload: IcpHealthResponse = {
        online: false, latencyMs: miitLatency, checkedAt, source: "miit",
        error: `ICP_Query（${ICP_BASE}）: ${icpErr}；MIIT: ${String(data?.msg || data?.code || "异常")}`,
      };
      void cacheResult(payload);
      return res.status(200).json(payload);
    }
    miitErr = String(data?.msg || data?.code || "不可用");
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "unknown";
    miitErr = msg.includes("abort") || msg.includes("timeout") ? "连接超时" : msg.slice(0, 60);
  }

  const payload: IcpHealthResponse = {
    online: false,
    latencyMs: icpLatency ?? miitLatency,
    checkedAt,
    source: "miit",
    error: `ICP 查询服务（${ICP_BASE}）不可用，MIIT 直连也不可用。ICP_Query: ${icpErr}；MIIT: ${miitErr}`,
  };
  void cacheResult(payload);
  return res.status(200).json(payload);
}

async function cacheResult(payload: IcpHealthResponse) {
  try {
    await setRedisValue(CACHE_KEY, JSON.stringify(payload), CACHE_TTL);
  } catch {
    // ignore
  }
}
