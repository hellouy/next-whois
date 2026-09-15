import type { SiteIdentity } from "./site-identity";

export interface BadgeBundle {
  textHtml: string;
  iconHtml: string;
  iconUrl: string;
  siteUrl: string;
  siteName: string;
}

export function escapeHtml(input: string): string {
  return String(input)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function textBadgeHtml(identity: Pick<SiteIdentity, "url" | "label">): string {
  const href = escapeHtml(identity.url || "#");
  const text = escapeHtml(identity.label || "site");
  return `<a href="${href}" target="_blank" rel="noopener noreferrer me">${text}</a>`;
}

export function iconBadgeHtml(
  identity: Pick<SiteIdentity, "url" | "label">,
  opts?: { iconUrl?: string },
): string {
  const href = escapeHtml(identity.url || "#");
  const text = escapeHtml(identity.label || "site");
  const iconUrl = opts?.iconUrl || `${identity.url.replace(/\/$/, "")}/favicon.ico`;
  const img = `<img src="${escapeHtml(iconUrl)}" alt="" width="16" height="16" style="width:16px;height:16px;border-radius:4px;object-fit:cover;flex:none;" />`;
  const inner = `<span style="display:inline-flex;align-items:center;gap:6px;font-size:14px;line-height:1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#0f172a;">
  ${img}
  ${text}<span style="color:#64748b;font-size:11px;">&#8599;</span>
</span>`;
  return `<a href="${href}" target="_blank" rel="noopener noreferrer me" style="text-decoration:none;">${inner}</a>`;
}

export function buildBadges(identity: Pick<SiteIdentity, "url" | "label">): BadgeBundle {
  const iconUrl = `${identity.url.replace(/\/$/, "")}/favicon.ico`;
  return {
    textHtml: textBadgeHtml(identity),
    iconHtml: iconBadgeHtml(identity, { iconUrl }),
    iconUrl,
    siteUrl: identity.url,
    siteName: identity.label,
  };
}