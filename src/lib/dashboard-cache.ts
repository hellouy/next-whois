import type { Subscription, Stamp } from "@/components/dashboard/types";

export interface SearchStats {
  total: number;
  today: number;
  thisWeek: number;
  available: number;
  highValue: number;
  topType: string | null;
}

export interface DashData {
  subscriptions: Subscription[];
  stamps: Stamp[];
  subscriptionAccess: boolean;
  subscriptionExpiresAt?: string | null;
  balanceCents?: number;
  membershipPlan?: string | null;
  searchStats: SearchStats | null;
}

let _dashCache: DashData | null = null;
let _dashCacheTs = 0;
export const DASH_CACHE_TTL = 60_000;

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
  };
  _dashCache = result;
  _dashCacheTs = Date.now();
  return result;
}

export function invalidateDashCache() {
  _dashCache = null;
  _dashCacheTs = 0;
}

export function getDashCache(): { data: DashData | null; fresh: boolean } {
  return {
    data: _dashCache,
    fresh: !!_dashCache && Date.now() - _dashCacheTs < DASH_CACHE_TTL,
  };
}
