import * as cheerio from "cheerio";
import { getSiteUrl } from "./site-settings-server";
import { getSiteLabel } from "@/lib/email";

export interface SiteIdentity {
  url: string;
  hostname: string;
  label: string;
}

function hostToken(hostname: string): string {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");
}

export async function resolveSiteIdentity(): Promise<SiteIdentity> {
  const url = (await getSiteUrl().catch(() => "")) || "";
  let hostname = "";
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = "";
  }
  const label = await getSiteLabel().catch(() => "WHOIS");
  return { url: url.replace(/\/$/, ""), hostname: hostToken(hostname), label: String(label).trim() };
}

export function normalizeHref(href: string): string {
  let h = String(href || "").trim();
  if (h.startsWith("//")) h = "https:" + h;
  try {
    const u = new URL(h, "https://example.invalid");
    if (!/^https?:/.test(u.protocol)) return "";
    return `${u.protocol}//${u.hostname.replace(/^www\./i, "")}${u.pathname.replace(/\/+$/, "")}`;
  } catch {
    return "";
  }
}

export interface MatchResult {
  found: boolean;
  reason?: string;
}

export function matchesSiteIdentity(html: string, identity: SiteIdentity): MatchResult {
  if (!html || html.trim().length === 0) return { found: false, reason: "empty" };

  const $ = cheerio.load(html);

  const labelLower = identity.label ? identity.label.toLowerCase() : "";
  const hostname = hostToken(identity.hostname);

  let matchedReason = "";
  const hrefMatched: string[] = [];

  $("a[href]").each((_i, el) => {
    const href = $(el).attr("href") || "";
    const norm = normalizeHref(href);
    if (!norm) return;

    let u: URL;
    try {
      u = new URL(norm);
    } catch {
      return;
    }
    const host = hostToken(u.hostname);
    if (host && hostname && host === hostname) {
      matchedReason = `href:${norm.slice(0, 90)}`;
      return false;
    }
    // text-only match: anchor text equals our site label
    if (labelLower) {
      const text = $(el).text().trim().toLowerCase();
      if (text && labelLower && text === labelLower) {
        hrefMatched.push(norm);
      }
    }
  });
  if (matchedReason) return { found: true, reason: matchedReason };

  if (hrefMatched.length > 0) {
    return { found: true, reason: `anchor:${hrefMatched[0]}` };
  }

  if (hostname && labelLower) {
    const body = $("body").text().toLowerCase();
    if (body.includes(labelLower)) {
      return { found: true, reason: "body-text" };
    }
    if (body.includes(hostname)) {
      return { found: true, reason: "body-domain" };
    }
  }

  return { found: false, reason: "none" };
}

export { hostToken };