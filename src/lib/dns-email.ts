// Pure parsing helpers for DNS email authentication records (SPF / DMARC).

export type SpfMechanism = {
  type: string;
  value?: string;
  qualifier: string;
};

export type SpfAnalysis = {
  mechanisms: SpfMechanism[];
  allDirective: string | null;
  dnsLookupCount: number;
  tooManyLookups: boolean;
  raw: string;
};

export type DmarcAnalysis = {
  p: string | null;
  sp: string | null;
  pct: string | null;
  rua: string[];
  ruf: string[];
  adkim: string | null;
  aspf: string | null;
  strength: "none" | "weak" | "strong";
  raw: string;
};

const DNS_LOOKUP_TYPES = ["include", "a", "mx", "exists", "ptr", "redirect"];

export function parseSpf(raw: string): SpfAnalysis {
  const parts = raw.split(/\s+/).filter(Boolean);
  const mechanisms: SpfMechanism[] = [];
  let allDirective: string | null = null;
  let dnsLookupCount = 0;

  for (const part of parts) {
    if (/^v=spf1$/i.test(part)) continue;
    // RFC 7208: `redirect=` (the canonical syntax) and `redirect:` both occur
    // in the wild; qualifiers are only valid on mechanism names, but tolerate
    // them before either separator for consistency.
    const match = part.match(/^([+\-~?]?)(\w+)(?:[:=](.+))?$/);
    if (!match) continue;
    const [, qualifier, type, value] = match;
    if (type.toLowerCase() === "all") { allDirective = (qualifier || "+") + "all"; continue; }
    if (type.toLowerCase() === "redirect") { dnsLookupCount++; }
    else if (DNS_LOOKUP_TYPES.includes(type.toLowerCase())) dnsLookupCount++;
    mechanisms.push({ type: type.toLowerCase(), value, qualifier: qualifier || "+" });
  }

  return { mechanisms, allDirective, dnsLookupCount, tooManyLookups: dnsLookupCount > 10, raw };
}

export function parseDmarc(raw: string): DmarcAnalysis {
  const tags: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const k = trimmed.slice(0, eq).trim().toLowerCase();
    const v = trimmed.slice(eq + 1).trim();
    if (k) tags[k] = v;
  }
  // Tag values are case-insensitive per RFC 7489 (mailto lists keep their case).
  const norm = (k: string): string | null => (k in tags ? tags[k].toLowerCase() : null);
  const p = norm("p");
  let strength: DmarcAnalysis["strength"] = "none";
  if (p === "reject") strength = "strong";
  else if (p === "quarantine") strength = "weak";
  else if (p === "none") strength = "none";

  const list = (k: string): string[] => {
    const v = tags[k];
    return v ? v.split(",").map(s => s.trim().replace(/^mailto:/i, "")).filter(Boolean) : [];
  };

  return {
    p, sp: norm("sp"), pct: norm("pct"),
    rua: list("rua"), ruf: list("ruf"),
    adkim: norm("adkim"), aspf: norm("aspf"),
    strength, raw,
  };
}
