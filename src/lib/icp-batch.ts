// Batch ICP search helpers: term splitting and result aggregation.

export const ICP_BATCH_MAX = 20;
export const ICP_BATCH_CONCURRENCY = 3;

export type IcpBatchItem = {
  search: string;
  ok: boolean;
  total: number;
  pages: number;
  list: unknown[];
  source?: string;
  error?: string;
};

export function splitSearchTerms(input: string): string[] {
  if (!input) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of input.split(/[\s,，\n]+/)) {
    const term = raw.trim();
    if (!term) continue;
    if (seen.has(term)) continue;
    seen.add(term);
    out.push(term);
    if (out.length >= ICP_BATCH_MAX) break;
  }
  return out;
}

export function countBatchFailed(items: Array<{ ok: boolean }>): number {
  return items.filter(i => !i.ok).length;
}
