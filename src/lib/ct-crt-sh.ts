// Certificate Transparency log lookup via crt.sh (free public interface).

const CT_TIMEOUT_MS = 8000;
const CT_MAX_ITEMS = 50;

export type CtLogEntry = {
  name_value: string;
  not_before: string;
  not_after: string;
  id: number;
};

export type CtResult = {
  available: boolean;
  total?: number;
  entries?: CtLogEntry[];
};

export async function fetchCtLogs(hostname: string): Promise<CtResult> {
  if (!hostname || hostname.match(/^(\d{1,3}\.){3}\d{1,3}$/) || hostname.includes(":")) {
    return { available: false };
  }
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(hostname)}&output=json`;
  try {
    const r = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "NextWhois/1.0" },
      signal: AbortSignal.timeout(CT_TIMEOUT_MS),
    });
    if (!r.ok) return { available: false };
    const data: any[] = await r.json();
    if (!Array.isArray(data)) return { available: false };

    const seen = new Set<number>();
    const entries: CtLogEntry[] = [];
    for (const item of data) {
      if (!item || typeof item !== "object") continue;
      const id = Number(item.id);
      if (!id || seen.has(id)) continue;
      seen.add(id);
      entries.push({
        name_value: String(item.name_value ?? ""),
        not_before: String(item.not_before ?? ""),
        not_after: String(item.not_after ?? ""),
        id,
      });
      if (entries.length >= CT_MAX_ITEMS) break;
    }
    return { available: true, total: data.length, entries };
  } catch {
    return { available: false };
  }
}
