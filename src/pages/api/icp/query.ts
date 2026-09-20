import type { NextApiRequest, NextApiResponse } from "next";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { queryMiitIcp, type MiitIcpPage } from "@/lib/server/icp-miit";
import { splitSearchTerms, countBatchFailed, ICP_BATCH_CONCURRENCY, type IcpBatchItem } from "@/lib/icp-batch";

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

export type IcpBatchResponse = {
  ok: boolean;
  batch: true;
  type: IcpType;
  results: IcpBatchItem[];
  failed: number;
  elapsedMs: number;
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

// Primary ICP data source — a self-hosted ICP_Query instance (HG-ha/ICP_Query)
// that wraps the MIIT filing database and solves its captcha. Defaults to the
// shared deployment at https://icp.ng; set ICP_API_BASE to point at your own
// instance (e.g. http://127.0.0.1:16181).
const UPSTREAM_BASE = (process.env.ICP_API_BASE ?? "https://icp.ng").replace(/\/$/, "");

async function fetchIcpQuery(
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
    source: "icpq",
  };
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<IcpResponse | IcpBatchResponse>,
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
  const rawSearch = (req.query.search as string | undefined) ?? "";
  const pageNum  = Math.max(1, parseInt((req.query.pageNum  as string) || "1",  10) || 1);
  const pageSize = Math.min(50, Math.max(1, parseInt((req.query.pageSize as string) || "10", 10) || 10));
  const batch = req.query.batch === "1" || req.query.batch === "true";

  if (!type || !VALID_TYPES.includes(type)) {
    return res.status(400).json({
      ok: false, type: "web", search: rawSearch, pageNum, pageSize,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: `无效的查询类型，支持: ${VALID_TYPES.join(", ")}`,
    });
  }

  res.setHeader("Cache-Control", "no-store");

  if (batch) {
    const terms = splitSearchTerms(rawSearch);
    if (terms.length === 0) {
      return res.status(400).json({
        ok: false, type, search: rawSearch, pageNum, pageSize,
        total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
        error: "search 参数不能为空",
      });
    }
    const t0 = Date.now();
    const results: IcpBatchItem[] = new Array(terms.length);
    let cursor = 0;
    const workerCount = Math.min(ICP_BATCH_CONCURRENCY, terms.length);
    const workers = Array.from({ length: workerCount }, async () => {
      for (;;) {
        const i = cursor++;
        if (i >= terms.length) return;
        const r = await queryOne(type, terms[i], pageNum, pageSize);
        const item: IcpBatchItem = {
          search: terms[i],
          ok: r.ok,
          total: r.total,
          pages: r.pages,
          list: r.list,
          ...(r.source ? { source: r.source } : {}),
          ...(r.error ? { error: r.error } : {}),
        };
        results[i] = item;
      }
    });
    await Promise.all(workers);
    return res.status(200).json({
      ok: true,
      batch: true,
      type,
      results,
      failed: countBatchFailed(results),
      elapsedMs: Date.now() - t0,
    });
  }

  const search = rawSearch.trim();
  if (!search) {
    return res.status(400).json({
      ok: false, type, search, pageNum, pageSize,
      total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
      error: "search 参数不能为空",
    });
  }

  // ── Single mode: keep existing response shape ─────────────────────────────
  const result = await queryOne(type, search, pageNum, pageSize);
  return res.status(result.ok ? 200 : 502).json(result);
}

// Shared single-term lookup: ICP_Query (icp.ng) primary + direct MIIT fallback.
async function queryOne(type: IcpType, search: string, pageNum: number, pageSize: number): Promise<IcpResponse> {
  // ── Primary: ICP_Query service (https://icp.ng by default) ────────────────
  const icpQuery = await fetchIcpQuery(type, search, pageNum, pageSize);
  if (icpQuery) {
    return icpQuery;
  }

  // ── Fallback: direct MIIT database client ─────────────────────────────────
  const miitResult = await queryMiitIcp({ type, search, pageNum, pageSize, timeoutMs: 12_000 });
  if (miitResult.ok) {
    return pageToResponse(miitResult.data, type, search);
  }

  // ── Both sources failed: return best error ────────────────────────────────
  const miitErr = miitResult.error;
  const miitCode = miitResult.code ?? 0;
  const miitTransient = miitCode === 500 || miitCode === -1 || miitCode === 401;

  const finalError = miitTransient
    ? `ICP 查询服务（${UPSTREAM_BASE}）不可用，回退 MIIT 直连也失败。${miitErr}`
    : miitErr;

  return {
    ok: false, type, search, pageNum, pageSize,
    total: 0, pages: 0, hasNextPage: false, hasPreviousPage: false, list: [],
    error: finalError,
  };
}
