import type { Subscription, Stamp } from "@/components/dashboard/types";

export interface SearchStats {
  total: number;
  today: number;
  thisWeek: number;
  available: number;
  highValue: number;
  topType: string | null;
}

export interface RecentSearch {
  query: string;
  query_type: string;
  reg_status: string | null;
  created_at: string;
}

export interface DashData {
  subscriptions: Subscription[];
  stamps: Stamp[];
  subscriptionAccess: boolean;
  subscriptionExpiresAt?: string | null;
  balanceCents?: number;
  membershipPlan?: string | null;
  searchStats: SearchStats | null;
  recentSearches?: RecentSearch[];
}

let _dashCache: DashData | null = null;
let _dashCacheTs = 0;
export const DASH_CACHE_TTL = 60_000;
const SESSION_KEY = "xrw_dash_cache";

function tryReadSession(): { data: DashData; ts: number } | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { data: DashData; ts: number };
    if (!parsed?.ts || !parsed?.data) return null;
    return parsed;
  } catch {
    return null;
  }
}

function tryWriteSession(data: DashData) {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ data, ts: Date.now() }));
  } catch {
    // sessionStorage may be unavailable (private mode quota, etc.)
  }
}

export async function fetchDashData(): Promise<DashData> {
  const res = await fetch("/api/user/dashboard");
  if (!res.ok) throw new Error(`${res.status}`);
  const data = await res.json();
  const result: DashData = {
    subscriptions: data.subscriptions ?? [],
    stamps: data.stamps ?? [],
    subscriptionAccess: data.subscriptionAccess ?? false,
    subscriptionExpiresAt: data.subscriptionExpiresAt ?? null,
    balanceCents: data.balanceCents ?? 0,
    membershipPlan: data.membershipPlan ?? null,
    searchStats: data.searchStats ?? null,
    recentSearches: data.recentSearches ?? [],
  };
  _dashCache = result;
  _dashCacheTs = Date.now();
  tryWriteSession(result);
  return result;
}

export function invalidateDashCache() {
  _dashCache = null;
  _dashCacheTs = 0;
  if (typeof window !== "undefined") {
    try { sessionStorage.removeItem(SESSION_KEY); } catch { /* */ }
  }
}

export function getDashCache(): { data: DashData | null; fresh: boolean } {
  // Memory cache first (fastest)
  if (_dashCache && Date.now() - _dashCacheTs < DASH_CACHE_TTL) {
    return { data: _dashCache, fresh: true };
  }
  // Fallback: sessionStorage (survives page navigation within the same tab session)
  const session = tryReadSession();
  if (session && Date.now() - session.ts < DASH_CACHE_TTL) {
    _dashCache = session.data;
    _dashCacheTs = session.ts;
    return { data: session.data, fresh: true };
  }
  // Stale but available (return stale + trigger background refresh)
  if (_dashCache) return { data: _dashCache, fresh: false };
  if (session) return { data: session.data, fresh: false };
  return { data: null, fresh: false };
}
