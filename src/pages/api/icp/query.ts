import type { NextApiRequest, NextApiResponse } from "next";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { queryMiitIcp, type MiitIcpPage } from "@/lib/server/icp-miit";

export const config = { maxDuration: 15 };

const RL_LIMIT  = 30;
const RL_WINDOW = 60_000;

const VALID_TYPES = ["web", "app", "mapp", "kapp", "bweb", "bapp", "bmapp", "bkapp"] as const;
type IcpType = typeof VALID_TYPES[number];

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
  cityId?: string | number | null;
  countyId?: string | number | null;
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
  source?: string;
};

function stripHtml(text: string): string {
  return text.replace(/<[^>]*>/g, " ").replace(/\s{2,}/g, " ").trim().slice(0, 120);
}

function isHtmlResponse(text: string): boolean {
  const t = text.trimStart().toLowerCase();
  return t.startsWith("<!doctype") || t.startsWith("<html");
}

function pageToResponse(p: MiitIcpPage, type: IcpType, search: string): IcpResponse {
  return {
    ok: true,
    type, search,
    pageNum: p.pageNum,
    pageSize: p.pageSize,
    total: p.total,
    pages: p.pages,
    hasNextPage: p.hasNextPage,
    hasPreviousPage: p.hasPreviousPage,
    list: p.list as IcpRecord[],
    source: "miit",
  };
}

// Legacy fallback: ICP_API_BASE (e.g. api.ong:16181 or a custom proxy).
// Vercel blocks non-standard ports, so this only works if ICP_API_BASE points
// to an HTTPS endpoint on port 443 that proxies MIIT data.
const UPSTREAM_BASE = (process.env.ICP_API_BASE ?? "http://api.ong:16181").replace(/\/$/, "");

async function fetchLegacyUpstream(
  type: IcpType,
  search: string,
  pageNum: number,
  pageSize: number,
): Promise<IcpResponse | null> {
  const url = `${UPSTREAM_BASE}/query/${encodeURIComponent(type)}?search=${encodeURIComponent(search)}&pageNum=${pageNum}&pageSize=${pageSize}`;
  async function doFetch(): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      return await fetch(url, {
        signal: controller.signal,
        headers: { Accept: "application/json", "User-Agent": "NextWhois/3.0" },
      });
    } finally {
      clearTimeout(timer);
    }
  }
  let r: Response;
  try {
    r = await doFetch();
    if (!r.ok && r.status >= 500) {
      await new Promise(res => setTimeout(res, 800));
      r = await doFetch();
    }
  } catch {
    try {
      await new Promise(res => setTimeout(res, 800));
      r = await doFetch();
    } catch {
      return null;
    }
  }
  if (!r.ok) return null;
  const ct = r.headers.get("content-type") ?? "";
  if (!ct.includes("json")) {
    const txt = await r.text().catch(() => "");
    if (isHtmlResponse(txt)) return null;
    return null;
  }
  const data = await r.json().catch(() => null);
  if (!data || (!data.success && data.code !== 200)) return null;
  const p = data.params ?? {};
  const list: IcpRecord[] = Array.isArray(p.list) ? p.list : [];
  return {
    ok: true, type, search,
    pageNum: p.pageNum ?? pageNum,
    pageSize: p.pageSize ?? pageSize,
    total: p.total ?? list.length,
    pages: p.pages ?? 1,
    hasNextPage: p.hasNextPage ?? false,
    hasPreviousPage: p.hasPreviousPage ?? false,
    list,
    source: "legacy",
  };
}

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

  const { ok: allowed } = await checkRateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) {
    return res.status(429).json({
      ok: false, type: "web", search: "", pageNum: 1, pageSize: 10,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: "请求过于频繁，请稍后再试",
    });
  }

  const type = (req.query.type as string | undefined)?.trim() as IcpType | undefined;
  const search = (req.query.search as string | undefined)?.trim() ?? "";
  const pageNum  = Math.max(1, parseInt((req.query.pageNum  as string) || "1",  10) || 1);
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

  res.setHeader("Cache-Control", "no-store");

  // ── Primary: direct MIIT ICP API ─────────────────────────────────────────
  const miitResult = await queryMiitIcp({ type, search, pageNum, pageSize, timeoutMs: 12_000 });

  if (miitResult.ok) {
    return res.status(200).json(pageToResponse(miitResult.data, type, search));
  }

  // Transient MIIT errors (server down, timeout, token issue) → try legacy fallback
  const miitErr = miitResult.error;
  const miitCode = miitResult.code ?? 0;
  const miitTransient = miitCode === 500 || miitCode === -1 || miitCode === 401;

  if (miitTransient) {
    const legacy = await fetchLegacyUpstream(type, search, pageNum, pageSize);
    if (legacy) {
      return res.status(200).json(legacy);
    }
  }

  // ── All sources failed: return best error ────────────────────────────────
  const hasCustomBase = process.env.ICP_API_BASE && process.env.ICP_API_BASE !== "http://api.ong:16181";
  const finalError = miitTransient
    ? miitErr + (hasCustomBase ? "" : "。如有自建代理，请设置 ICP_API_BASE 环境变量")
    : miitErr;

  return res.status(502).json({
    ok: false, type, search, pageNum, pageSize,
    total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
    error: finalError,
  });
}
