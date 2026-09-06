// Pure helpers shared between batch-scrape.mjs and vitest unit tests.
// No side effects, no network, no DB — safe to import anywhere.

export const AUTHORITY_ORDER = ["registry","registrar","icann","wiki","search","wayback","iana"];

export function sanitizeTimezone(v) {
  const VALID = new Set(Intl.supportedValuesOf("timeZone"));
  if (typeof v !== "string" || !v) return null;
  const tz = v.trim();
  if (tz === "UTC" || tz === "Etc/UTC") return tz === "Etc/UTC" ? "UTC" : tz;
  return VALID.has(tz) ? tz : null;
}

export function isAllDefaults(r) {
  return r.grace_period_days === 30 && r.redemption_period_days === 30 && r.pending_delete_days === 5;
}

export function isProblematic(r) {
  const total = r.grace_period_days + r.redemption_period_days + r.pending_delete_days;
  const isZero = total === 0 && !r.reasoning?.toLowerCase().match(/instant|immediately|sofort|unmittelbar/);
  return isAllDefaults(r) || isZero;
}

export function parseAiJson(content) {
  const c = content
    .replace(/^```json\s*/i,"").replace(/^```\s*/i,"").replace(/```\s*$/,"")
    .replace(/^[^{]*({[\s\S]*})[^}]*$/,"$1").trim();
  const p = JSON.parse(c);
  const toInt = (v, min=0) => Math.max(min, parseInt(String(v)) || 0);
  const toNullInt = (v, lo, hi) => {
    if (v===null||v===undefined||v==="") return null;
    const n = parseInt(String(v));
    if (isNaN(n)) return null;
    return (n < lo || n > hi) ? null : n;
  };
  const clampInt = (v, lo, hi) => {
    const n = parseInt(String(v));
    return isNaN(n) ? 0 : Math.min(hi, Math.max(lo, n));
  };
  const validChannels = new Set(AUTHORITY_ORDER);
  const fs = (p.fields_source && typeof p.fields_source === "object") ? p.fields_source : {};
  const srcOf = f => {
    const v = fs[f];
    return typeof v === "string" && validChannels.has(v) ? v : "industry_default";
  };
  return {
    grace_period_days:      toInt(p.grace_period_days),
    redemption_period_days: toInt(p.redemption_period_days),
    pending_delete_days:    toInt(p.pending_delete_days),
    pre_expiry_days:        clampInt(p.pre_expiry_days, 0, 365),
    drop_hour:              toNullInt(p.drop_hour, 0, 23),
    drop_minute:            toNullInt(p.drop_minute, 0, 59),
    drop_second:            toNullInt(p.drop_second, 0, 59),
    drop_timezone:          sanitizeTimezone(p.drop_timezone),
    reasoning: String(p.reasoning||"").slice(0, 800),
    fields_source: {
      grace_period_days:      srcOf("grace_period_days"),
      redemption_period_days: srcOf("redemption_period_days"),
      pending_delete_days:    srcOf("pending_delete_days"),
      drop_hour:              srcOf("drop_hour"),
      drop_timezone:          srcOf("drop_timezone"),
    },
  };
}

// Order channel snapshots by authority (highest first).
export function sortByAuthority(channels) {
  return [...channels].sort((a, b) => AUTHORITY_ORDER.indexOf(a.channel) - AUTHORITY_ORDER.indexOf(b.channel));
}

// Compact fetch_strategy label from collected channels.
export function strategyOf(channels) {
  const oks = channels.filter(c => c.status === "ok");
  if (oks.length === 0) return "none";
  const names = oks.map(c => c.channel);
  return names.length === 1 ? names[0] : names.join("+");
}

// Does any field carry a real (non-industry-default) channel source?
export function hasRealSource(fieldsSource) {
  if (!fieldsSource) return false;
  return Object.values(fieldsSource).some(s => s && s !== "industry_default");
}
