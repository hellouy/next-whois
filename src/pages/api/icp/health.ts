import type { NextApiRequest, NextApiResponse } from "next";
import { getRedisValue, setRedisValue } from "@/lib/server/redis";

export const config = { maxDuration: 12 };

export type IcpHealthResponse = {
  online: boolean;
  latencyMs: number | null;
  checkedAt: string;
  source?: "miit" | "legacy";
  error?: string;
};

const MIIT_AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth";
const CACHE_KEY = "icp:health:status";
const CACHE_TTL = 300; // 5 minutes — MIIT health rarely flips

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

  // ── Check MIIT direct access (primary source) ────────────────────────────
  const t0 = Date.now();
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
    const latencyMs = Date.now() - t0;
    const data = await authRes.json().catch(() => null);
    const miitOnline = data?.success === true || data?.code === 200;

    if (miitOnline) {
      const payload: IcpHealthResponse = { online: true, latencyMs, checkedAt, source: "miit" };
      void cacheResult(payload);
      return res.status(200).json(payload);
    }

    // code 500 = MIIT server error (service down); fall through to legacy check
    if (data?.code !== 500 && data?.code !== undefined) {
      const payload: IcpHealthResponse = {
        online: false, latencyMs, checkedAt, source: "miit",
        error: `MIIT: ${String(data?.msg || data?.code || "异常")}`,
      };
      void cacheResult(payload);
      return res.status(200).json(payload);
    }

    // code 500 means MIIT backend down → check legacy fallback
    const miitLatency = latencyMs;

    const icpBase = (process.env.ICP_API_BASE ?? "http://api.ong:16181").replace(/\/$/, "");
    const t1 = Date.now();
    const controller2 = new AbortController();
    const timer2 = setTimeout(() => controller2.abort(), 8000);
    let legacyOnline = false;
    let legacyErr = "不可用";
    try {
      const legacyRes = await fetch(
        `${icpBase}/query/web?search=miit.gov.cn&pageNum=1&pageSize=1`,
        {
          signal: controller2.signal,
          headers: { Accept: "application/json", "User-Agent": "NextWhois/3.0" },
        },
      );
      const legacyData = await legacyRes.json().catch(() => null);
      legacyOnline = legacyData?.success === true || legacyData?.code === 200;
      if (!legacyOnline) legacyErr = String(legacyData?.msg || legacyData?.message || `HTTP ${legacyRes.status}`);
    } catch (e: unknown) {
      legacyErr = e instanceof Error ? e.message.slice(0, 60) : "连接失败";
    } finally {
      clearTimeout(timer2);
    }
    const legacyLatency = Date.now() - t1;

    if (legacyOnline) {
      const payload: IcpHealthResponse = { online: true, latencyMs: legacyLatency, checkedAt, source: "legacy" };
      void cacheResult(payload);
      return res.status(200).json(payload);
    }

    const payload: IcpHealthResponse = {
      online: false,
      latencyMs: miitLatency,
      checkedAt,
      source: "miit",
      error: `MIIT 服务异常（code 500），备用服务: ${legacyErr}`,
    };
    void cacheResult(payload);
    return res.status(200).json(payload);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "unknown";
    const latencyMs = Date.now() - t0;
    const isTimeout = msg.includes("abort") || msg.includes("timeout");
    const payload: IcpHealthResponse = {
      online: false,
      latencyMs: isTimeout ? null : latencyMs,
      checkedAt,
      source: "miit",
      error: isTimeout ? "MIIT 连接超时" : msg.slice(0, 80),
    };
    // Don't cache error/timeout results — let next request retry
    return res.status(200).json(payload);
  }
}

async function cacheResult(payload: IcpHealthResponse) {
  try {
    await setRedisValue(CACHE_KEY, JSON.stringify(payload), CACHE_TTL);
  } catch {
    // ignore
  }
}
