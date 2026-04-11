import type { IncomingMessage } from "http";
import { strEnv } from "@/lib/env";

export const siteTitle = strEnv(
  "NEXT_PUBLIC_SITE_TITLE",
  "RDAP+WHOIS - Domain Lookup Tool",
);
export const siteDescription = strEnv(
  "NEXT_PUBLIC_SITE_DESCRIPTION",
  "快速查询域名、IP、ASN、CIDR 的 WHOIS / RDAP 信息，支持多节点并行查询。",
);
export const siteKeywords = strEnv(
  "NEXT_PUBLIC_SITE_KEYWORDS",
  "Whois, RDAP, Lookup, Domain, IPv4, IPv6, ASN, CIDR",
);

const configuredUrl = strEnv("NEXT_PUBLIC_SITE_URL", "");

export function getOrigin(req?: IncomingMessage): string {
  if (configuredUrl) return configuredUrl;
  if (!req) return "";
  const proto = req.headers["x-forwarded-proto"] || "https";
  const host = req.headers.host;
  return host ? `${proto}://${host}` : "";
}
