/**
 * Direct MIIT ICP registration database client.
 *
 * Authentication flow (bypasses Knownsec CloudWAF):
 *   1. POST to /api/auth  → get __jsluid_s WAF cookie + auth token
 *   2. POST to /api/icpAbbreviateInfo/queryByCondition
 *      with Cookie: __jsluid_s=... and token: <auth_token>
 *
 * The WAF cookie is enough to bypass the IP-based block on the query endpoint.
 * The auth token grants MIIT-level access.
 *
 * serviceType mapping:
 *   1 = web (网站)   2 = app (APP)   3 = mapp (小程序)   4 = kapp (快应用)
 * Blacklist types use the same query with blackListLevel filtering in results.
 */

const MIIT_AUTH_URL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth";
const MIIT_QUERY_URL =
  "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition";
const MIIT_BLACKLIST_URL =
  "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/blackList/queryByCondition";

const MIIT_ORIGIN = "https://beian.miit.gov.cn";
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

function baseHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Origin": MIIT_ORIGIN,
    "Referer": MIIT_ORIGIN + "/",
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    ...extra,
  };
}

function randomKey(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < 32; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

export type MiitIcpRecord = {
  contentTypeName?: string;
  domain?: string;
  domainId?: number | string;
  leaderName?: string;
  limitAccess?: string | boolean;
  mainId?: number | string;
  mainLicence?: string;
  natureName?: string;
  serviceId?: number | string;
  serviceLicence?: string;
  serviceName?: string;
  unitName?: string;
  updateRecordTime?: string;
  cityId?: string | number | null;
  countyId?: string | number | null;
  mainUnitAddress?: string;
  blackListLevel?: string | number;
  version?: string;
};

export type MiitIcpPage = {
  list: MiitIcpRecord[];
  total: number;
  pages: number;
  pageNum: number;
  pageSize: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  isFirstPage: boolean;
  isLastPage: boolean;
  nextPage: number;
  size: number;
  startRow: number;
  endRow: number;
  navigateLastPage: number;
};

export type MiitIcpResult =
  | { ok: true; data: MiitIcpPage }
  | { ok: false; error: string; code?: number };

const TYPE_MAP: Record<string, number> = {
  web: 1, app: 2, mapp: 3, kapp: 4,
  bweb: 1, bapp: 2, bmapp: 3, bkapp: 4,
};

function isBlacklistType(type: string): boolean {
  return type.startsWith("b");
}

async function miitFetch(
  url: string,
  body: string,
  cookie: string,
  token: string,
  timeoutMs: number,
): Promise<{ status: number; json: unknown; newCookie?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: {
        ...baseHeaders({
          "Content-Type": "application/json;charset=UTF-8",
          ...(cookie ? { Cookie: cookie } : {}),
          ...(token ? { token } : {}),
        }),
      },
      body,
    });
    const text = await res.text();
    let json: unknown;
    try { json = JSON.parse(text); } catch { json = text; }
    const setCookie = res.headers.get("set-cookie") ?? "";
    const newCookie = setCookie ? setCookie.split(";")[0] : undefined;
    return { status: res.status, json, newCookie };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Execute an ICP lookup against the MIIT database.
 * Handles the full authentication flow internally.
 */
export async function queryMiitIcp(opts: {
  type: string;
  search: string;
  pageNum: number;
  pageSize: number;
  timeoutMs?: number;
}): Promise<MiitIcpResult> {
  const { type, search, pageNum, pageSize, timeoutMs = 12_000 } = opts;
  const serviceType = TYPE_MAP[type] ?? 1;
  const isBlacklist = isBlacklistType(type);

  // ── Step 1: Get auth token + WAF cookie ──────────────────────────────────
  const authKey = randomKey();
  const authBody = JSON.stringify({ authKey, timeStamp: Date.now() });

  let wafCookie = "";
  let authToken = "";

  try {
    const authRes = await miitFetch(MIIT_AUTH_URL, authBody, "", "", Math.min(timeoutMs, 8_000));
    if (authRes.newCookie) wafCookie = authRes.newCookie;

    const authData = authRes.json as Record<string, unknown>;
    if (authData?.success === true || authData?.code === 200) {
      authToken = String(authData.data ?? "");
    } else if (authData?.code === 500) {
      return { ok: false, error: "MIIT ICP 服务暂时不可用，请稍后重试（auth服务器异常）", code: 500 };
    } else {
      return {
        ok: false,
        error: `ICP 认证失败 (code: ${authData?.code ?? "?"}): ${String(authData?.msg ?? "未知错误")}`,
        code: typeof authData?.code === "number" ? authData.code : undefined,
      };
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("abort") || msg.includes("timeout")) {
      return { ok: false, error: "ICP 认证超时，MIIT 服务可能暂时不可用，请稍后重试", code: -1 };
    }
    return { ok: false, error: `ICP 认证请求失败: ${msg.slice(0, 100)}`, code: -2 };
  }

  // ── Step 2: Query ICP data ────────────────────────────────────────────────
  const queryUrl = isBlacklist ? MIIT_BLACKLIST_URL : MIIT_QUERY_URL;
  const queryBody = JSON.stringify({
    pageNum,
    pageSize,
    serviceType,
    unitName: "",
    serviceName: search,
  });

  try {
    const qRes = await miitFetch(queryUrl, queryBody, wafCookie, authToken, Math.min(timeoutMs, 10_000));
    const data = qRes.json as Record<string, unknown>;

    if (data?.success === true || data?.code === 200) {
      const p = (data.params ?? {}) as Record<string, unknown>;
      const list = Array.isArray(p.list) ? (p.list as MiitIcpRecord[]) : [];
      return {
        ok: true,
        data: {
          list,
          total:            typeof p.total === "number" ? p.total : list.length,
          pages:            typeof p.pages === "number" ? p.pages : 1,
          pageNum:          typeof p.pageNum === "number" ? p.pageNum : pageNum,
          pageSize:         typeof p.pageSize === "number" ? p.pageSize : pageSize,
          hasNextPage:      Boolean(p.hasNextPage),
          hasPreviousPage:  Boolean(p.hasPreviousPage),
          isFirstPage:      Boolean(p.isFirstPage ?? true),
          isLastPage:       Boolean(p.isLastPage ?? true),
          nextPage:         typeof p.nextPage === "number" ? p.nextPage : 0,
          size:             typeof p.size === "number" ? p.size : list.length,
          startRow:         typeof p.startRow === "number" ? p.startRow : 1,
          endRow:           typeof p.endRow === "number" ? p.endRow : list.length,
          navigateLastPage: typeof p.navigateLastPage === "number" ? p.navigateLastPage : 1,
        },
      };
    }

    if (data?.code === 401) {
      return { ok: false, error: "ICP 查询授权失败，请重试（token无效）", code: 401 };
    }

    const errMsg = String((data as Record<string, unknown>)?.msg ?? "未知错误");
    return { ok: false, error: `ICP 查询失败 (code ${data?.code ?? "?"}): ${errMsg}`, code: typeof data?.code === "number" ? (data.code as number) : undefined };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("abort") || msg.includes("timeout")) {
      return { ok: false, error: "ICP 查询超时（MIIT 服务响应慢），请稍后重试", code: -1 };
    }
    return { ok: false, error: `ICP 查询请求失败: ${msg.slice(0, 100)}`, code: -2 };
  }
}
