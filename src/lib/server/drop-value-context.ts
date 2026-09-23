/**
 * Server-side loader that assembles the {@link ValueContext} used by
 * `scoreDomainExtended`. Hot prefixes come from the shared cache so the
 * drop pipeline stays in sync with `/api/admin/hot-prefixes`.
 */

import { getHotPrefixes } from "@/lib/server/hot-prefix-cache";
import { buildHotPrefixMap, type ValueContext } from "@/lib/drop-value";

export async function loadValueContext(): Promise<ValueContext> {
  const prefixes = await getHotPrefixes();
  return { hotPrefixes: buildHotPrefixMap(prefixes) };
}
