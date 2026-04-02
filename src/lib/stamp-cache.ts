const _cache = new Map<string, { stamps: any[]; ts: number }>();
export const STAMP_CACHE_TTL = 60_000;

export function getStampCache(domain: string) {
  return _cache.get(domain);
}

export function setStampCache(domain: string, stamps: any[]) {
  _cache.set(domain, { stamps, ts: Date.now() });
}

export function invalidateStampCache(domain: string) {
  _cache.delete(domain);
}
