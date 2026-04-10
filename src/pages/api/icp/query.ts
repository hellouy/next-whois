import type { NextApiRequest, NextApiResponse } from "next";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 15 };

const RL_LIMIT  = 30;
const RL_WINDOW = 60_000;

const VALID_TYPES = ["web", "app", "mapp", "kapp", "bweb", "bapp", "bmapp", "bkapp"] as const;
type IcpType = typeof VALID_TYPES[number];

/** Actual response shape from api.ong:16181 */
type UpstreamParams = {
  list: IcpRecord[];
  total: number;
  pages: number;
  pageNum: number;
  pageSize: number;
  nextPage: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  isFirstPage: boolean;
  isLastPage: boolean;
  navigateLastPage: number;
  size: number;
  startRow: number;
  endRow: number;
};

type UpstreamResponse = {
  code: number;
  msg: string;
  success: boolean;
  params: UpstreamParams;
};

export type IcpRecord = {
  domain?: string;
  domainId?: number | string;
  limitAccess?: string | boolean;
  mainLicence?: string;
  natureName?: string;
  serviceLicence?: string;
  unitName?: string;
  leaderName?: string;
  updateRecordTime?: string;
  contentTypeName?: string;
  cityId?: string | number;
  countyId?: string | number;
  mainUnitAddress?: string;
  serviceName?: string;
  serviceId?: number | string;
  mainId?: number | string;
  version?: string;
  blackListLevel?: string | number;
};

export type IcpResponse = {
  ok: boolean;
  type: IcpType;
  search: string;
  pageNum: number;
  pageSize: number;
  total: number;
  pages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  list: IcpRecord[];
  error?: string;
};

function stripHtml(text: string): string {
  return text.replace(/<[^>]*>/g, " ").replace(/\s{2,}/g, " ").trim().slice(0, 120);
}

function isHtmlResponse(text: string): boolean {
  const t = text.trimStart().toLowerCase();
  return t.startsWith("<!doctype") || t.startsWith("<html");
}

// ICP_API_BASE can be set in Vercel environment variables to point to a custom
// ICP backend accessible from cloud infrastructure (port 16181 is blocked by Vercel).
// Example: ICP_API_BASE=https://your-icp-proxy.example.com
const UPSTREAM_BASE = (process.env.ICP_API_BASE ?? "http://api.ong:16181").replace(/\/$/, "");

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<IcpResponse>,
) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      ok: false, type: "web", search: "", pageNum: 1, pageSize: 10,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: "Method not allowed",
    });
  }

  // Rate limiting: 30 requests per minute per IP
  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) {
    return res.status(429).json({
      ok: false, type: "web", search: "", pageNum: 1, pageSize: 10,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: "请求过于频繁，请稍后再试",
    });
  }

  const type = (req.query.type as string | undefined)?.trim() as IcpType | undefined;
  const search = (req.query.search as string | undefined)?.trim() ?? "";
  const pageNum = Math.max(1, parseInt((req.query.pageNum as string) || "1", 10) || 1);
  const pageSize = Math.min(50, Math.max(1, parseInt((req.query.pageSize as string) || "10", 10) || 10));

  if (!type || !VALID_TYPES.includes(type)) {
    return res.status(400).json({
      ok: false, type: "web", search, pageNum, pageSize,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: `无效的查询类型，支持: ${VALID_TYPES.join(", ")}`,
    });
  }

  if (!search) {
    return res.status(400).json({
      ok: false, type, search, pageNum, pageSize,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: "search 参数不能为空",
    });
  }

  try {
    const upstream = `${UPSTREAM_BASE}/query/${encodeURIComponent(type)}?search=${encodeURIComponent(search)}&pageNum=${pageNum}&pageSize=${pageSize}`;

    async function fetchUpstream(): Promise<Response> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      try {
        return await fetch(upstream, {
          signal: controller.signal,
          headers: { Accept: "application/json", "User-Agent": "NextWhois/2.0" },
        });
      } finally {
        clearTimeout(timer);
      }
    }

    let upstreamRes: Response;
    try {
      upstreamRes = await fetchUpstream();
      if (!upstreamRes.ok && upstreamRes.status >= 500) {
        await new Promise(r => setTimeout(r, 1200));
        upstreamRes = await fetchUpstream();
      }
    } catch (firstErr) {
      await new Promise(r => setTimeout(r, 1200));
      upstreamRes = await fetchUpstream();
    }

    if (!upstreamRes.ok) {
      const text = await upstreamRes.text().catch(() => "");
      const clean = isHtmlResponse(text)
        ? `数据服务暂时不可用（HTTP ${upstreamRes.status}），请稍后重试`
        : `上游接口错误（HTTP ${upstreamRes.status}）：${stripHtml(text)}`;
      return res.status(502).json({
        ok: false, type, search, pageNum, pageSize,
        total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
        error: clean,
      });
    }

    const contentType = upstreamRes.headers.get("content-type") ?? "";
    if (!contentType.includes("json")) {
      const text = await upstreamRes.text().catch(() => "");
      const clean = isHtmlResponse(text)
        ? "数据服务返回了非 JSON 响应，可能正在维护，请稍后重试"
        : `意外响应：${text.slice(0, 100)}`;
      return res.status(502).json({
        ok: false, type, search, pageNum, pageSize,
        total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
        error: clean,
      });
    }

    const data: UpstreamResponse = await upstreamRes.json();

    if (!data.success && data.code !== 200) {
      return res.status(200).json({
        ok: false, type, search, pageNum, pageSize,
        total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
        error: data.msg || "查询失败",
      });
    }

    const p = data.params ?? ({} as UpstreamParams);
    const list: IcpRecord[] = Array.isArray(p.list) ? p.list : [];

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      ok: true, type, search,
      pageNum: p.pageNum ?? pageNum,
      pageSize: p.pageSize ?? pageSize,
      total: p.total ?? list.length,
      pages: p.pages ?? 1,
      hasNextPage: p.hasNextPage ?? false,
      hasPreviousPage: p.hasPreviousPage ?? false,
      list,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "未知错误";
    const isTimeout = msg.includes("abort") || msg.includes("timeout");
    const isNoConn = msg.includes("ENOTFOUND") || msg.includes("ECONNREFUSED") || msg.includes("fetch failed");
    const isPortBlocked = msg.includes("ECONNREFUSED") || (isNoConn && !msg.includes("ENOTFOUND"));
    const clean = isTimeout
      ? "备案查询超时（>12s）。Vercel 等云平台会屏蔽非标端口（16181），请在环境变量 ICP_API_BASE 中配置可访问的后端地址，或直接前往 beian.miit.gov.cn 手动查询"
      : isPortBlocked
      ? "无法连接到备案数据服务（端口被防火墙屏蔽）。请配置环境变量 ICP_API_BASE 或直接访问 beian.miit.gov.cn"
      : isNoConn
      ? "无法连接到备案数据服务。请配置环境变量 ICP_API_BASE 指向可用的 ICP 查询后端"
      : `查询失败：${msg.slice(0, 100)}`;
    return res.status(502).json({
      ok: false, type, search, pageNum, pageSize,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: clean,
    });
  }
}
