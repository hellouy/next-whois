import { ImageResponse } from "next/og";
import { NextRequest } from "next/server";
import { getEppStatusDisplayName } from "@/lib/whois/epp_status";

export const config = { runtime: "edge" };

function detectType(q: string): string {
  if (!q) return "unknown";
  if (/^AS\d+$/i.test(q)) return "ASN";
  if (/\/\d{1,3}$/.test(q)) return "CIDR";
  if (q.includes(":")) return "IPv6";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) return "IPv4";
  return "DOMAIN";
}

function getRelativeTime(dateStr: string): string {
  if (!dateStr || dateStr === "Unknown") return "";
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return "";
    const now = new Date();
    const diffDays = Math.floor(
      (now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24),
    );
    if (diffDays < 0) {
      const abs = Math.abs(diffDays);
      if (abs < 30) return `in ${abs}d`;
      if (abs < 365) return `in ${Math.floor(abs / 30)}mo`;
      return `in ${Math.floor(abs / 365)}y`;
    }
    if (diffDays < 1) return "today";
    if (diffDays < 30) return `${diffDays}d ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago`;
    return `${Math.floor(diffDays / 365)}y ago`;
  } catch {
    return "";
  }
}

function isValid(v: string | undefined | null): v is string {
  return !!v && v !== "Unknown" && v !== "N/A" && v !== "";
}

function formatDate(dateStr: string): string {
  if (!dateStr || dateStr === "Unknown") return "";
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return dateStr;
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  } catch {
    return dateStr;
  }
}

function hashCode(str: string): number {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

function parseEnabledStyles(raw: unknown): number[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    return [0, 1, 2, 3, 4, 5, 6, 7];
  }
  const parsed = (raw as unknown[])
    .map((v) => Number(v))
    .filter((n) => !isNaN(n) && n >= 0 && n <= 7);
  return parsed.length > 0 ? parsed : [0, 1, 2, 3, 4, 5, 6, 7];
}

export default async function handler(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const query = searchParams.get("query") || searchParams.get("q") || "";
  const w = Math.min(
    Math.max(parseInt(searchParams.get("w") || "1200") || 1200, 200),
    4096,
  );
  const h = Math.min(
    Math.max(parseInt(searchParams.get("h") || "630") || 630, 200),
    4096,
  );
  const theme = searchParams.get("theme") === "dark" ? "dark" : "light";
  const styleParam = searchParams.get("style");
  const preview = searchParams.get("preview") === "1";

  const isDark = theme === "dark";
  const bg = isDark ? "#09090b" : "#fafafa";
  const fg = isDark ? "#fafafa" : "#18181b";
  const muted = isDark ? "#a1a1aa" : "#71717a";
  const border = isDark ? "#27272a" : "#e4e4e7";
  const accent = isDark ? "#3b82f6" : "#2563eb";
  const cardBg = isDark ? "#18181b" : "#ffffff";
  const subtleBg = isDark ? "#27272a" : "#f4f4f5";
  const greenColor = isDark ? "#4ade80" : "#16a34a";
  const redColor = "#ef4444";
  const amberColor = isDark ? "#fbbf24" : "#d97706";

  const queryType = query ? detectType(query) : "unknown";

  const typeBadgeColors: Record<string, { bg: string; fg: string }> = {
    DOMAIN: {
      bg: isDark ? "#1e3a5f" : "#dbeafe",
      fg: isDark ? "#60a5fa" : "#2563eb",
    },
    IPv4: {
      bg: isDark ? "#064e3b" : "#d1fae5",
      fg: isDark ? "#34d399" : "#059669",
    },
    IPv6: {
      bg: isDark ? "#2e1065" : "#ede9fe",
      fg: isDark ? "#a78bfa" : "#7c3aed",
    },
    ASN: {
      bg: isDark ? "#431407" : "#ffedd5",
      fg: isDark ? "#fb923c" : "#ea580c",
    },
    CIDR: {
      bg: isDark ? "#500724" : "#fce7f3",
      fg: isDark ? "#f472b6" : "#db2777",
    },
    unknown: { bg: subtleBg, fg: muted },
  };
  const typeBadge = typeBadgeColors[queryType] || typeBadgeColors.unknown;

  const typeGradients: Record<string, string> = {
    DOMAIN: "linear-gradient(135deg,#1d4ed8 0%,#7c3aed 100%)",
    IPv4: "linear-gradient(135deg,#059669 0%,#0891b2 100%)",
    IPv6: "linear-gradient(135deg,#7c3aed 0%,#c026d3 100%)",
    ASN: "linear-gradient(135deg,#ea580c 0%,#ca8a04 100%)",
    CIDR: "linear-gradient(135deg,#db2777 0%,#e11d48 100%)",
    unknown: "linear-gradient(135deg,#374151 0%,#1f2937 100%)",
  };
  const typeGradient = typeGradients[queryType] || typeGradients.unknown;

  let registrar = "";
  let created = "";
  let expires = "";
  let updated = "";
  let statusList: string[] = [];
  let nsList: string[] = [];
  let age = "";
  let remainingDays: number | null = null;
  let dnssec = "";
  let whoisServer = "";
  let registrantOrg = "";
  let country = "";
  let hasDetails = false;

  const origin = new URL(req.url).origin;

  // ── Inline data fast path ────────────────────────────────────────────────
  // When the OG URL is generated server-side (result page), key WHOIS fields
  // are embedded as compact URL params, so we never need to call /api/lookup.
  const hasInlineData =
    searchParams.has("cr") ||
    searchParams.has("ex") ||
    searchParams.has("reg") ||
    searchParams.has("rd");

  if (hasInlineData) {
    const regP = searchParams.get("reg");
    const crP  = searchParams.get("cr");
    const exP  = searchParams.get("ex");
    const upP  = searchParams.get("up");
    const rdP  = searchParams.get("rd");
    const ageP = searchParams.get("age");
    const nsP  = searchParams.get("ns");
    const stP  = searchParams.get("st");
    const coP  = searchParams.get("co");
    const orgP = searchParams.get("org");
    const dnP  = searchParams.get("dn");
    const wsP  = searchParams.get("ws");

    if (regP) registrar = regP;
    if (crP)  created   = crP;
    if (exP)  expires   = exP;
    if (upP)  updated   = upP;
    if (rdP !== null) remainingDays = parseInt(rdP, 10);
    if (ageP) age = ageP;
    if (nsP)  nsList    = nsP.split(",").filter(Boolean);
    if (stP)  statusList = stP.split(",").filter(Boolean).map(s => getEppStatusDisplayName(s));
    if (coP)  country   = coP;
    if (orgP) registrantOrg = orgP;
    if (dnP)  dnssec    = dnP;
    if (wsP)  whoisServer = wsP;
    hasDetails = !!(registrar || created || expires);
  }

  // ── Helper: fetch with hard timeout ─────────────────────────────────────
  async function fetchWithTimeout(url: string, ms: number): Promise<Response | null> {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      const res = await fetch(url, { signal: ctrl.signal });
      clearTimeout(timer);
      return res;
    } catch {
      clearTimeout(timer);
      return null;
    }
  }

  // ── Remote fetch (fallback when no inline data) ──────────────────────────
  // og-config is a cheap, well-cached endpoint; lookup is only called when
  // the OG URL was opened directly without embedded params (e.g. bot first hit
  // before the page was ever visited), capped at 5 s to avoid slow responses.
  const [configRes, lookupRes] = await Promise.all([
    fetch(`${origin}/api/og-config`).catch(() => null),
    !preview && query && !hasInlineData
      ? fetchWithTimeout(
          `${origin}/api/lookup?query=${encodeURIComponent(query)}`,
          5000,
        )
      : Promise.resolve(null),
  ]);

  let enabledStyles = [0, 1, 2, 3, 4, 5, 6, 7];
  let brandName = "RDAP+WHOIS";
  let tagline = "WHOIS / RDAP · Domain Lookup Tool";
  if (configRes?.ok) {
    try {
      const cfg = await configRes.json();
      enabledStyles = parseEnabledStyles(cfg.enabled_styles);
      if (cfg.brand_name) brandName = cfg.brand_name;
      if (cfg.tagline) tagline = cfg.tagline;
    } catch {}
  }

  if (!hasInlineData && lookupRes?.ok) {
    try {
      const data = await lookupRes.json();
      if (data.status && data.result) {
        const r = data.result;
        if (isValid(r.registrar)) registrar = r.registrar;
        if (isValid(r.creationDate)) created = formatDate(r.creationDate);
        if (isValid(r.expirationDate)) expires = formatDate(r.expirationDate);
        if (isValid(r.updatedDate)) updated = formatDate(r.updatedDate);
        if (Array.isArray(r.status) && r.status.length > 0) {
          statusList = r.status
            .slice(0, 6)
            .map((s: { status: string }) => getEppStatusDisplayName(s.status));
        }
        if (Array.isArray(r.nameServers) && r.nameServers.length > 0) {
          nsList = r.nameServers.slice(0, 4);
        }
        if (r.domainAge != null) age = String(r.domainAge);
        if (r.remainingDays != null) remainingDays = r.remainingDays;
        if (isValid(r.dnssec)) dnssec = r.dnssec;
        if (isValid(r.whoisServer)) whoisServer = r.whoisServer;
        if (isValid(r.registrantOrganization))
          registrantOrg = r.registrantOrganization;
        if (isValid(r.registrantCountry)) country = r.registrantCountry;
        hasDetails = !!(registrar || created || expires);
      }
    } catch {}
  }

  const statusColor =
    remainingDays === null
      ? muted
      : remainingDays <= 0
        ? redColor
        : remainingDays <= 60
          ? amberColor
          : greenColor;
  const statusLabel =
    remainingDays === null
      ? "N/A"
      : remainingDays <= 0
        ? "EXPIRED"
        : remainingDays <= 60
          ? "EXPIRING SOON"
          : "ACTIVE";

  const createdRelative = created ? getRelativeTime(created) : "";
  const expiresRelative =
    remainingDays !== null
      ? remainingDays > 0
        ? `${remainingDays}d remaining`
        : "Expired"
      : expires
        ? getRelativeTime(expires)
        : "";
  const updatedRelative = updated ? getRelativeTime(updated) : "";

  const domainFontSize = Math.min(
    84,
    Math.max(36, Math.floor(900 / Math.max(query.length, 1))),
  );

  const styleVariant =
    styleParam !== null
      ? Math.min(7, Math.max(0, parseInt(styleParam) || 0))
      : query
        ? enabledStyles[hashCode(query) % enabledStyles.length]
        : enabledStyles[0] ?? 0;

  const dotGrid = `radial-gradient(${isDark ? "#27272a" : "#d4d4d8"} 1px, transparent 1px)`;
  const hostHeader = req.headers.get("host") || new URL(req.url).host;
  const siteHost = hostHeader.replace(/:\d+$/, "") || "RDAP+WHOIS";

  const logoW = (size: number, bg2: string, fg2: string, radius = 6) => (
    <div
      style={{
        width: `${size}px`,
        height: `${size}px`,
        backgroundColor: bg2,
        color: fg2,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: `${radius}px`,
        fontSize: `${Math.round(size * 0.55)}px`,
        fontWeight: 700,
        flexShrink: 0,
      }}
    >
      W
    </div>
  );

  let content: JSX.Element;

  if (query && hasDetails) {
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          backgroundColor: bg,
          backgroundImage: dotGrid,
          backgroundSize: "24px 24px",
          padding: "40px",
          position: "relative",
        }}
      >
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            width: "100%",
            maxWidth: "1040px",
            backgroundColor: cardBg,
            border: `1px solid ${border}`,
            borderRadius: "20px",
            padding: "40px 48px 32px",
            gap: "20px",
            boxShadow: isDark
              ? "0 8px 40px rgba(0,0,0,0.4)"
              : "0 8px 40px rgba(0,0,0,0.07)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
            }}
          >
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "6px",
                flex: 1,
                minWidth: 0,
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: "8px" }}
              >
                <div
                  style={{
                    padding: "3px 10px",
                    borderRadius: "4px",
                    backgroundColor: typeBadge.bg,
                    fontSize: "11px",
                    fontWeight: 700,
                    color: typeBadge.fg,
                    letterSpacing: "0.08em",
                    display: "flex",
                  }}
                >
                  {queryType}
                </div>
                {age && (
                  <div
                    style={{
                      padding: "3px 10px",
                      borderRadius: "4px",
                      backgroundColor: subtleBg,
                      fontSize: "11px",
                      fontWeight: 500,
                      color: muted,
                      display: "flex",
                    }}
                  >
                    {`${age} ${parseInt(age) === 1 ? "year" : "years"}`}
                  </div>
                )}
              </div>
              <span
                style={{
                  fontSize: Math.min(
                    54,
                    Math.max(
                      28,
                      Math.floor((780 / Math.max(query.length, 1)) * 1.5),
                    ),
                  ),
                  fontWeight: 700,
                  color: fg,
                  letterSpacing: "-0.02em",
                  lineHeight: 1.15,
                }}
              >
                {query}
              </span>
              {registrar && (
                <span
                  style={{
                    fontSize: "14px",
                    color: muted,
                    fontWeight: 400,
                    marginTop: "2px",
                    display: "flex",
                  }}
                >
                  {registrar}
                  {registrantOrg && registrantOrg !== registrar
                    ? ` · ${registrantOrg}`
                    : ""}
                </span>
              )}
            </div>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "flex-end",
                gap: "6px",
                marginLeft: "20px",
                flexShrink: 0,
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "6px 14px",
                  borderRadius: "10px",
                  backgroundColor: `${statusColor}18`,
                  border: `1px solid ${statusColor}40`,
                }}
              >
                <div
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    backgroundColor: statusColor,
                  }}
                />
                <span
                  style={{
                    fontSize: "13px",
                    fontWeight: 700,
                    color: statusColor,
                    letterSpacing: "0.04em",
                    display: "flex",
                  }}
                >
                  {statusLabel}
                </span>
              </div>
              {remainingDays !== null && remainingDays > 0 && (
                <span
                  style={{
                    fontSize: "11px",
                    color: muted,
                    fontWeight: 500,
                    display: "flex",
                  }}
                >
                  {`${remainingDays}d remaining`}
                </span>
              )}
            </div>
          </div>

          <div
            style={{
              display: "flex",
              borderTop: `1px solid ${border}`,
              paddingTop: "18px",
              gap: "40px",
              flexWrap: "wrap",
            }}
          >
            {created && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                <span
                  style={{
                    fontSize: "10px",
                    color: muted,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    display: "flex",
                  }}
                >
                  CREATED
                </span>
                <span
                  style={{
                    fontSize: "16px",
                    color: fg,
                    fontWeight: 600,
                    fontFamily: "monospace",
                    display: "flex",
                  }}
                >
                  {created}
                </span>
                {createdRelative && (
                  <span
                    style={{
                      fontSize: "11px",
                      color: muted,
                      fontWeight: 400,
                      display: "flex",
                    }}
                  >
                    {createdRelative}
                  </span>
                )}
              </div>
            )}
            {expires && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                <span
                  style={{
                    fontSize: "10px",
                    color: muted,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    display: "flex",
                  }}
                >
                  EXPIRES
                </span>
                <span
                  style={{
                    fontSize: "16px",
                    color: fg,
                    fontWeight: 600,
                    fontFamily: "monospace",
                    display: "flex",
                  }}
                >
                  {expires}
                </span>
                {expiresRelative && (
                  <span
                    style={{
                      fontSize: "11px",
                      color:
                        remainingDays !== null && remainingDays <= 60
                          ? amberColor
                          : greenColor,
                      fontWeight: 500,
                      display: "flex",
                    }}
                  >
                    {expiresRelative}
                  </span>
                )}
              </div>
            )}
            {updated && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                <span
                  style={{
                    fontSize: "10px",
                    color: muted,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    display: "flex",
                  }}
                >
                  UPDATED
                </span>
                <span
                  style={{
                    fontSize: "16px",
                    color: fg,
                    fontWeight: 600,
                    fontFamily: "monospace",
                    display: "flex",
                  }}
                >
                  {updated}
                </span>
                {updatedRelative && (
                  <span
                    style={{
                      fontSize: "11px",
                      color: muted,
                      fontWeight: 400,
                      display: "flex",
                    }}
                  >
                    {updatedRelative}
                  </span>
                )}
              </div>
            )}
            {country && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                  marginLeft: "auto",
                }}
              >
                <span
                  style={{
                    fontSize: "10px",
                    color: muted,
                    fontWeight: 600,
                    letterSpacing: "0.08em",
                    display: "flex",
                  }}
                >
                  COUNTRY
                </span>
                <span
                  style={{
                    fontSize: "16px",
                    color: fg,
                    fontWeight: 600,
                    display: "flex",
                  }}
                >
                  {country}
                </span>
              </div>
            )}
          </div>

          {(statusList.length > 0 || nsList.length > 0 || whoisServer) && (
            <div
              style={{
                display: "flex",
                gap: "32px",
                flexWrap: "wrap",
                borderTop: `1px solid ${border}`,
                paddingTop: "14px",
              }}
            >
              {statusList.length > 0 && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "10px",
                      color: muted,
                      fontWeight: 600,
                      letterSpacing: "0.08em",
                      display: "flex",
                    }}
                  >
                    STATUS
                  </span>
                  <div
                    style={{ display: "flex", gap: "5px", flexWrap: "wrap" }}
                  >
                    {statusList.map((s) => (
                      <div
                        key={s}
                        style={{
                          padding: "2px 8px",
                          borderRadius: "4px",
                          backgroundColor: subtleBg,
                          fontSize: "10px",
                          color: muted,
                          fontWeight: 500,
                          fontFamily: "monospace",
                          display: "flex",
                        }}
                      >
                        {s.trim()}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {nsList.length > 0 && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "10px",
                      color: muted,
                      fontWeight: 600,
                      letterSpacing: "0.08em",
                      display: "flex",
                    }}
                  >
                    NAMESERVERS
                  </span>
                  <div
                    style={{ display: "flex", gap: "5px", flexWrap: "wrap" }}
                  >
                    {nsList.map((n) => (
                      <div
                        key={n}
                        style={{
                          padding: "2px 8px",
                          borderRadius: "4px",
                          backgroundColor: subtleBg,
                          fontSize: "10px",
                          color: muted,
                          fontWeight: 500,
                          fontFamily: "monospace",
                          display: "flex",
                        }}
                      >
                        {n.trim().toLowerCase()}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {whoisServer && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                  }}
                >
                  <span
                    style={{
                      fontSize: "10px",
                      color: muted,
                      fontWeight: 600,
                      letterSpacing: "0.08em",
                      display: "flex",
                    }}
                  >
                    WHOIS SERVER
                  </span>
                  <span
                    style={{
                      fontSize: "11px",
                      color: muted,
                      fontWeight: 500,
                      fontFamily: "monospace",
                      display: "flex",
                    }}
                  >
                    {whoisServer}
                  </span>
                </div>
              )}
            </div>
          )}

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              borderTop: `1px solid ${border}`,
              paddingTop: "16px",
              marginTop: "4px",
            }}
          >
            <div
              style={{ display: "flex", alignItems: "center", gap: "8px" }}
            >
              {logoW(24, fg, bg, 4)}
              <span
                style={{
                  fontSize: "13px",
                  color: muted,
                  fontWeight: 600,
                  letterSpacing: "0.04em",
                  display: "flex",
                }}
              >
                {brandName}
              </span>
            </div>
            <div
              style={{ display: "flex", alignItems: "center", gap: "16px" }}
            >
              {dnssec && (
                <span
                  style={{
                    fontSize: "11px",
                    color: muted,
                    fontFamily: "monospace",
                    display: "flex",
                  }}
                >
                  DNSSEC: {dnssec}
                </span>
              )}
              <span
                style={{
                  fontSize: "12px",
                  color: accent,
                  fontWeight: 500,
                  display: "flex",
                }}
              >
                {siteHost}
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  } else if (styleVariant === 1) {
    // ── Style 1: Gradient Left Panel ─────────────────────────────────────────
    const panelBg = isDark
      ? "linear-gradient(145deg,#1d2a6e 0%,#4c1d95 100%)"
      : "linear-gradient(145deg,#1d4ed8 0%,#7c3aed 100%)";
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          backgroundColor: bg,
        }}
      >
        <div
          style={{
            width: "300px",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            padding: "52px 40px",
            backgroundImage: panelBg,
            flexShrink: 0,
          }}
        >
          <div
            style={{ display: "flex", flexDirection: "column", gap: "14px" }}
          >
            {logoW(44, "rgba(255,255,255,0.9)", "rgba(0,0,0,0.7)", 10)}
            <span
              style={{
                fontSize: "16px",
                fontWeight: 700,
                color: "rgba(255,255,255,0.9)",
                letterSpacing: "0.06em",
                display: "flex",
              }}
            >
              {brandName}
            </span>
          </div>
          <div
            style={{ display: "flex", flexDirection: "column", gap: "12px" }}
          >
            <div
              style={{
                padding: "7px 16px",
                borderRadius: "8px",
                backgroundColor: "rgba(255,255,255,0.15)",
                border: "1px solid rgba(255,255,255,0.25)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <span
                style={{
                  fontSize: "13px",
                  fontWeight: 700,
                  color: "rgba(255,255,255,0.95)",
                  letterSpacing: "0.08em",
                  display: "flex",
                }}
              >
                {queryType}
              </span>
            </div>
            <span
              style={{
                fontSize: "12px",
                color: "rgba(255,255,255,0.55)",
                display: "flex",
              }}
            >
              Domain Intelligence
            </span>
          </div>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            padding: "52px 56px",
          }}
        >
          <div />
          <div
            style={{ display: "flex", flexDirection: "column", gap: "16px" }}
          >
            <span
              style={{
                fontSize: domainFontSize,
                fontWeight: 700,
                color: fg,
                letterSpacing: "-0.025em",
                lineHeight: 1.1,
                display: "flex",
                wordBreak: "break-all",
              }}
            >
              {query || "WHOIS Lookup"}
            </span>
            <span
              style={{
                fontSize: "17px",
                color: muted,
                fontWeight: 400,
                display: "flex",
              }}
            >
              {tagline}
            </span>
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              borderTop: `1px solid ${border}`,
              paddingTop: "24px",
            }}
          >
            <span
              style={{
                fontSize: "14px",
                color: muted,
                fontWeight: 500,
                display: "flex",
              }}
            >
              {siteHost}
            </span>
            <span
              style={{
                fontSize: "13px",
                color: accent,
                fontWeight: 500,
                display: "flex",
              }}
            >
              NIC.RW 提供支持
            </span>
          </div>
        </div>
      </div>
    );
  } else if (styleVariant === 2) {
    // ── Style 2: Terminal Dark ────────────────────────────────────────────────
    const termBg = "#0a0a0a";
    const termGreen = "#4ade80";
    const termMuted = "#52525b";
    const termFg = "#f4f4f5";
    const termBorder = "#1f1f1f";
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: termBg,
          padding: "52px 64px",
        }}
      >
        <div
          style={{ display: "flex", alignItems: "center", gap: "12px" }}
        >
          {logoW(32, termFg, termBg, 6)}
          <span
            style={{
              fontSize: "13px",
              fontWeight: 600,
              color: termMuted,
              letterSpacing: "0.1em",
              fontFamily: "monospace",
              display: "flex",
            }}
          >
            {brandName}
          </span>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            gap: "18px",
          }}
        >
          <div
            style={{ display: "flex", alignItems: "center", gap: "10px" }}
          >
            <span
              style={{
                fontSize: "15px",
                color: termGreen,
                fontFamily: "monospace",
                display: "flex",
              }}
            >
              $
            </span>
            <span
              style={{
                fontSize: "15px",
                color: termMuted,
                fontFamily: "monospace",
                display: "flex",
              }}
            >
              {`whois ${query || "example.com"}`}
            </span>
          </div>
          <div
            style={{ display: "flex", flexDirection: "column", gap: "6px" }}
          >
            <span
              style={{
                fontSize: "11px",
                color: termMuted,
                fontFamily: "monospace",
                letterSpacing: "0.1em",
                display: "flex",
              }}
            >
              DOMAIN NAME
            </span>
            <span
              style={{
                fontSize: domainFontSize,
                fontWeight: 700,
                color: termFg,
                fontFamily: "monospace",
                letterSpacing: "-0.01em",
                lineHeight: 1.1,
                display: "flex",
                wordBreak: "break-all",
              }}
            >
              {query || "WHOIS Lookup"}
            </span>
          </div>
          <div
            style={{ display: "flex", alignItems: "center", gap: "8px" }}
          >
            <div
              style={{
                padding: "4px 12px",
                borderRadius: "4px",
                backgroundColor: "#1a3520",
                border: `1px solid ${termGreen}40`,
                display: "flex",
              }}
            >
              <span
                style={{
                  fontSize: "12px",
                  color: termGreen,
                  fontFamily: "monospace",
                  fontWeight: 600,
                  display: "flex",
                }}
              >
                {queryType}
              </span>
            </div>
            <div
              style={{
                padding: "4px 12px",
                borderRadius: "4px",
                backgroundColor: "#1a1a1a",
                border: `1px solid ${termBorder}`,
                display: "flex",
              }}
            >
              <span
                style={{
                  fontSize: "12px",
                  color: termMuted,
                  fontFamily: "monospace",
                  display: "flex",
                }}
              >
                LOOKUP
              </span>
            </div>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            borderTop: `1px solid ${termBorder}`,
            paddingTop: "24px",
          }}
        >
          <span
            style={{
              fontSize: "13px",
              color: termMuted,
              fontFamily: "monospace",
              display: "flex",
            }}
          >
            {tagline}
          </span>
          <span
            style={{
              fontSize: "13px",
              color: termGreen,
              fontFamily: "monospace",
              fontWeight: 600,
              display: "flex",
            }}
          >
            {siteHost}
          </span>
        </div>
      </div>
    );
  } else if (styleVariant === 3) {
    // ── Style 3: Header Bar ───────────────────────────────────────────────────
    const headerBg = isDark ? "#1d4ed8" : "#2563eb";
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: bg,
        }}
      >
        <div
          style={{
            height: "80px",
            backgroundColor: headerBg,
            display: "flex",
            alignItems: "center",
            padding: "0 56px",
            gap: "14px",
            flexShrink: 0,
          }}
        >
          {logoW(38, "rgba(255,255,255,0.9)", "rgba(30,64,175,0.8)", 8)}
          <span
            style={{
              fontSize: "20px",
              fontWeight: 700,
              color: "white",
              letterSpacing: "0.04em",
              display: "flex",
            }}
          >
            {brandName}
          </span>
          <div style={{ flex: 1 }} />
          <div
            style={{
              padding: "5px 18px",
              borderRadius: "9999px",
              backgroundColor: "rgba(255,255,255,0.2)",
              border: "1px solid rgba(255,255,255,0.3)",
              display: "flex",
            }}
          >
            <span
              style={{
                fontSize: "13px",
                fontWeight: 700,
                color: "white",
                letterSpacing: "0.06em",
                display: "flex",
              }}
            >
              {queryType}
            </span>
          </div>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            padding: "40px 64px",
            gap: "20px",
            backgroundImage: dotGrid,
            backgroundSize: "24px 24px",
          }}
        >
          <span
            style={{
              fontSize: domainFontSize,
              fontWeight: 700,
              color: fg,
              letterSpacing: "-0.025em",
              lineHeight: 1.1,
              textAlign: "center",
              display: "flex",
              wordBreak: "break-all",
            }}
          >
            {query || "WHOIS Lookup Tool"}
          </span>
          <div
            style={{
              width: "64px",
              height: "4px",
              backgroundColor: headerBg,
              borderRadius: "9999px",
              display: "flex",
            }}
          />
          {!query && (
            <span
              style={{
                fontSize: "18px",
                color: muted,
                textAlign: "center",
                display: "flex",
              }}
            >
              Domain · IPv4 · IPv6 · ASN · CIDR
            </span>
          )}
        </div>

        <div
          style={{
            height: "68px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 56px",
            borderTop: `1px solid ${border}`,
            backgroundColor: cardBg,
            flexShrink: 0,
          }}
        >
          <span
            style={{
              fontSize: "14px",
              color: muted,
              fontWeight: 500,
              display: "flex",
            }}
          >
            {siteHost} · Domain Intelligence
          </span>
          <span
            style={{
              fontSize: "13px",
              color: accent,
              fontWeight: 500,
              display: "flex",
            }}
          >
            NIC.RW 提供支持
          </span>
        </div>
      </div>
    );
  } else if (styleVariant === 4) {
    // ── Style 4: Premium Dark (Ultra Minimal) ─────────────────────────────────
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: "#0a0a0a",
        }}
      >
        <div
          style={{ height: "4px", backgroundColor: "#3b82f6", width: "100%", flexShrink: 0 }}
        />
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            padding: "56px 80px",
            gap: "22px",
          }}
        >
          <span
            style={{
              fontSize: domainFontSize,
              fontWeight: 700,
              color: "#fafafa",
              letterSpacing: "-0.03em",
              lineHeight: 1.05,
              textAlign: "center",
              display: "flex",
              wordBreak: "break-all",
            }}
          >
            {query || "WHOIS Lookup Tool"}
          </span>
          <div
            style={{ display: "flex", alignItems: "center", gap: "12px" }}
          >
            <div
              style={{
                width: "32px",
                height: "1px",
                backgroundColor: "#3f3f46",
                display: "flex",
              }}
            />
            <span
              style={{
                fontSize: "12px",
                color: "#52525b",
                letterSpacing: "0.14em",
                fontWeight: 500,
                display: "flex",
              }}
            >
              {query ? `${queryType} LOOKUP` : "DOMAIN · IPV4 · IPV6 · ASN · CIDR"}
            </span>
            <div
              style={{
                width: "32px",
                height: "1px",
                backgroundColor: "#3f3f46",
                display: "flex",
              }}
            />
          </div>
        </div>
        <div
          style={{
            height: "64px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 64px",
            borderTop: "1px solid #1c1c1e",
            flexShrink: 0,
          }}
        >
          <div
            style={{ display: "flex", alignItems: "center", gap: "10px" }}
          >
            {logoW(28, "#fafafa", "#09090b", 6)}
            <span
              style={{
                fontSize: "14px",
                color: "#71717a",
                fontWeight: 500,
                letterSpacing: "0.04em",
                display: "flex",
              }}
            >
              {brandName}
            </span>
          </div>
          <span
            style={{
              fontSize: "13px",
              color: "#3b82f6",
              fontWeight: 500,
              display: "flex",
            }}
          >
            {siteHost}
          </span>
        </div>
      </div>
    );
  } else if (styleVariant === 5) {
    // ── Style 5: Blueprint (Technical Dark) – rendered grid lines ─────────────
    const blueprintBg = "#0f172a";
    const cyan = "#67e8f9";
    const cyanDim = "#22d3ee";
    const cyanFaint = "#164e63";
    const gridColor = "#1e3a5f";

    // Build horizontal + vertical grid paths as SVG
    const cols = 16;
    const rows = 10;
    const hPaths = Array.from({ length: rows - 1 }, (_, i) => {
      const y = Math.round(((i + 1) / rows) * h);
      return `M0 ${y} L${w} ${y}`;
    }).join(" ");
    const vPaths = Array.from({ length: cols - 1 }, (_, i) => {
      const x = Math.round(((i + 1) / cols) * w);
      return `M${x} 0 L${x} ${h}`;
    }).join(" ");

    // Corner marker size
    const cm = 20;

    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: blueprintBg,
          padding: "0",
          position: "relative",
        }}
      >
        {/* SVG grid overlay */}
        <svg
          width={w}
          height={h}
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: "100%",
            height: "100%",
          }}
        >
          <path d={hPaths} stroke={gridColor} strokeWidth="1" fill="none" />
          <path d={vPaths} stroke={gridColor} strokeWidth="1" fill="none" />
        </svg>

        {/* Content frame */}
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            margin: "32px",
            border: `1px solid ${cyanFaint}`,
            padding: "36px 52px",
            gap: "0",
            position: "relative",
          }}
        >
          {/* Corner markers – top-left */}
          <div style={{ position: "absolute", top: "-1px", left: "-1px", display: "flex" }}>
            <div style={{ width: `${cm}px`, height: "2px", backgroundColor: cyan, display: "flex" }} />
          </div>
          <div style={{ position: "absolute", top: "-1px", left: "-1px", display: "flex" }}>
            <div style={{ width: "2px", height: `${cm}px`, backgroundColor: cyan, display: "flex" }} />
          </div>
          {/* Corner markers – top-right */}
          <div style={{ position: "absolute", top: "-1px", right: "-1px", display: "flex" }}>
            <div style={{ width: `${cm}px`, height: "2px", backgroundColor: cyan, display: "flex" }} />
          </div>
          <div style={{ position: "absolute", top: "-1px", right: "-1px", display: "flex" }}>
            <div style={{ width: "2px", height: `${cm}px`, backgroundColor: cyan, display: "flex" }} />
          </div>
          {/* Corner markers – bottom-left */}
          <div style={{ position: "absolute", bottom: "-1px", left: "-1px", display: "flex" }}>
            <div style={{ width: `${cm}px`, height: "2px", backgroundColor: cyan, display: "flex" }} />
          </div>
          <div style={{ position: "absolute", bottom: "-1px", left: "-1px", display: "flex" }}>
            <div style={{ width: "2px", height: `${cm}px`, backgroundColor: cyan, display: "flex" }} />
          </div>
          {/* Corner markers – bottom-right */}
          <div style={{ position: "absolute", bottom: "-1px", right: "-1px", display: "flex" }}>
            <div style={{ width: `${cm}px`, height: "2px", backgroundColor: cyan, display: "flex" }} />
          </div>
          <div style={{ position: "absolute", bottom: "-1px", right: "-1px", display: "flex" }}>
            <div style={{ width: "2px", height: `${cm}px`, backgroundColor: cyan, display: "flex" }} />
          </div>

          {/* Header row */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              borderBottom: `1px solid ${cyanFaint}`,
              paddingBottom: "18px",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                color: "#475569",
                letterSpacing: "0.12em",
                fontFamily: "monospace",
                display: "flex",
              }}
            >
              {`${brandName} · DOMAIN LOOKUP SYSTEM`}
            </span>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: cyan, display: "flex" }} />
              <span style={{ fontSize: "10px", color: cyan, fontFamily: "monospace", letterSpacing: "0.1em", display: "flex" }}>ONLINE</span>
            </div>
          </div>

          {/* Main content */}
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              gap: "14px",
              padding: "24px 0",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                color: cyanDim,
                letterSpacing: "0.16em",
                fontFamily: "monospace",
                display: "flex",
              }}
            >
              QUERY_TARGET
            </span>
            <span
              style={{
                fontSize: domainFontSize,
                fontWeight: 700,
                color: "#f1f5f9",
                letterSpacing: "-0.02em",
                lineHeight: 1.1,
                fontFamily: "monospace",
                display: "flex",
                wordBreak: "break-all",
              }}
            >
              {query || "WHOIS"}
            </span>
            <div
              style={{ display: "flex", alignItems: "center", gap: "12px" }}
            >
              <div
                style={{
                  padding: "4px 12px",
                  borderRadius: "3px",
                  border: `1px solid ${cyan}`,
                  display: "flex",
                }}
              >
                <span
                  style={{
                    fontSize: "12px",
                    color: cyan,
                    fontFamily: "monospace",
                    fontWeight: 700,
                    display: "flex",
                  }}
                >
                  {queryType}
                </span>
              </div>
              <span
                style={{
                  fontSize: "11px",
                  color: "#334155",
                  fontFamily: "monospace",
                  display: "flex",
                }}
              >
                {`protocol: ${brandName}`}
              </span>
            </div>
          </div>

          {/* Footer row */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              borderTop: `1px solid ${cyanFaint}`,
              paddingTop: "18px",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                color: "#334155",
                fontFamily: "monospace",
                display: "flex",
              }}
            >
              {tagline}
            </span>
            <span
              style={{
                fontSize: "12px",
                color: cyan,
                fontFamily: "monospace",
                fontWeight: 600,
                display: "flex",
              }}
            >
              {siteHost}
            </span>
          </div>
        </div>
      </div>
    );
  } else if (styleVariant === 6) {
    // ── Style 6: Editorial Frame ───────────────────────────────────────────────
    const paperBg = "#f8f8f5";
    const ink = "#18181b";
    const inkMuted = "#71717a";
    const inkLight = "#e4e4e7";
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          backgroundColor: paperBg,
          padding: "20px",
        }}
      >
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            border: `2px solid ${ink}`,
            padding: "32px 52px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              borderBottom: `1px solid ${inkLight}`,
              paddingBottom: "18px",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                fontWeight: 700,
                color: ink,
                letterSpacing: "0.18em",
                display: "flex",
              }}
            >
              {brandName}
            </span>
            <div
              style={{ display: "flex", alignItems: "center", gap: "16px" }}
            >
              <span
                style={{
                  fontSize: "11px",
                  color: inkMuted,
                  letterSpacing: "0.1em",
                  display: "flex",
                }}
              >
                {queryType} LOOKUP
              </span>
              <div
                style={{
                  width: "1px",
                  height: "14px",
                  backgroundColor: inkLight,
                  display: "flex",
                }}
              />
              <span
                style={{
                  fontSize: "11px",
                  color: inkMuted,
                  letterSpacing: "0.08em",
                  display: "flex",
                }}
              >
                {siteHost}
              </span>
            </div>
          </div>

          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "24px 0",
            }}
          >
            <span
              style={{
                fontSize: Math.min(
                  domainFontSize * 0.88,
                  72,
                ),
                fontWeight: 900,
                color: "#09090b",
                letterSpacing: "-0.03em",
                lineHeight: 1.0,
                textAlign: "center",
                display: "flex",
                wordBreak: "break-all",
              }}
            >
              {(query || "WHOIS LOOKUP TOOL").toUpperCase()}
            </span>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              borderTop: `1px solid ${inkLight}`,
              paddingTop: "18px",
            }}
          >
            <span
              style={{
                fontSize: "11px",
                color: inkMuted,
                letterSpacing: "0.1em",
                display: "flex",
              }}
            >
              DOMAIN INTELLIGENCE PLATFORM
            </span>
            <span
              style={{
                fontSize: "11px",
                color: "#2563eb",
                fontWeight: 700,
                letterSpacing: "0.1em",
                display: "flex",
              }}
            >
              NIC.RW
            </span>
          </div>
        </div>
      </div>
    );
  } else if (styleVariant === 7) {
    // ── Style 7: Type Gradient ────────────────────────────────────────────────
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundImage: typeGradient,
          padding: "52px 64px",
        }}
      >
        <div
          style={{ display: "flex", alignItems: "center", gap: "12px" }}
        >
          {logoW(34, "rgba(255,255,255,0.2)", "white", 8)}
          <span
            style={{
              fontSize: "15px",
              fontWeight: 700,
              color: "rgba(255,255,255,0.85)",
              letterSpacing: "0.06em",
              display: "flex",
            }}
          >
            {brandName}
          </span>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            gap: "20px",
          }}
        >
          <span
            style={{
              fontSize: domainFontSize,
              fontWeight: 700,
              color: "white",
              letterSpacing: "-0.025em",
              lineHeight: 1.1,
              display: "flex",
              wordBreak: "break-all",
            }}
          >
            {query || "WHOIS Lookup Tool"}
          </span>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              alignSelf: "flex-start",
            }}
          >
            <div
              style={{
                padding: "5px 18px",
                borderRadius: "9999px",
                backgroundColor: "rgba(255,255,255,0.2)",
                border: "1px solid rgba(255,255,255,0.35)",
                display: "flex",
              }}
            >
              <span
                style={{
                  fontSize: "13px",
                  color: "white",
                  fontWeight: 700,
                  letterSpacing: "0.06em",
                  display: "flex",
                }}
              >
                {queryType}
              </span>
            </div>
            {!query && (
              <span
                style={{
                  fontSize: "15px",
                  color: "rgba(255,255,255,0.65)",
                  display: "flex",
                }}
              >
                Domain · IPv4 · IPv6 · ASN · CIDR
              </span>
            )}
          </div>
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            borderTop: "1px solid rgba(255,255,255,0.2)",
            paddingTop: "24px",
          }}
        >
          <span
            style={{
              fontSize: "14px",
              color: "rgba(255,255,255,0.65)",
              display: "flex",
            }}
          >
            Domain Intelligence · NIC.RW 提供支持
          </span>
          <span
            style={{
              fontSize: "14px",
              color: "rgba(255,255,255,0.9)",
              fontWeight: 600,
              display: "flex",
            }}
          >
            {siteHost}
          </span>
        </div>
      </div>
    );
  } else {
    // ── Style 0: Minimal Center (default) ─────────────────────────────────────
    content = (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: bg,
          backgroundImage: dotGrid,
          backgroundSize: "24px 24px",
          padding: "52px 64px",
        }}
      >
        <div
          style={{ display: "flex", alignItems: "center", gap: "10px" }}
        >
          {logoW(36, fg, bg, 8)}
          <span
            style={{
              fontSize: "16px",
              fontWeight: 600,
              color: muted,
              letterSpacing: "0.06em",
              display: "flex",
            }}
          >
            {brandName}
          </span>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: "20px",
          }}
        >
          <span
            style={{
              fontSize: domainFontSize,
              fontWeight: 700,
              color: fg,
              letterSpacing: "-0.025em",
              lineHeight: 1.1,
              textAlign: "center",
              display: "flex",
              wordBreak: "break-all",
            }}
          >
            {query || "WHOIS Lookup Tool"}
          </span>
          {query ? (
            <div
              style={{
                padding: "5px 16px",
                borderRadius: "9999px",
                backgroundColor: typeBadge.bg,
                fontSize: "15px",
                color: typeBadge.fg,
                fontWeight: 700,
                letterSpacing: "0.06em",
                display: "flex",
                alignItems: "center",
              }}
            >
              {`${queryType} LOOKUP`}
            </div>
          ) : (
            <span
              style={{
                fontSize: "18px",
                color: muted,
                textAlign: "center",
                display: "flex",
              }}
            >
              Domain · IPv4 · IPv6 · ASN · CIDR
            </span>
          )}
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            borderTop: `1px solid ${border}`,
            paddingTop: "24px",
          }}
        >
          <span
            style={{
              fontSize: "14px",
              color: muted,
              fontWeight: 500,
              display: "flex",
            }}
          >
            {siteHost} · Domain Intelligence Platform
          </span>
          <span
            style={{
              fontSize: "13px",
              color: accent,
              fontWeight: 500,
              display: "flex",
            }}
          >
            NIC.RW 提供支持
          </span>
        </div>
      </div>
    );
  }

  const cacheSeconds = preview ? 300 : 3600;
  return new ImageResponse(content, {
    width: w,
    height: h,
    headers: {
      "Cache-Control": `public, s-maxage=${cacheSeconds}, stale-while-revalidate=${cacheSeconds * 4}`,
    },
  });
}
