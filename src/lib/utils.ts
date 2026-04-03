import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import React from "react";
import { toast } from "sonner";
import { parse } from "tldts";
import { getSpecialDomain } from "@/lib/whois/lib";
import { useTranslation } from "@/lib/i18n";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function isEnter(e: React.KeyboardEvent) {
  // compatible with MacOS
  return e.key === "Enter" && e.keyCode !== 229;
}

export function saveAsFile(filename: string, content: string) {
  /**
   * Save text as file
   * @param filename Filename
   * @param content File content
   * @example
   * saveAsFile("hello.txt", "Hello world!");
   * @see https://developer.mozilla.org/en-US/docs/Web/API/Blob
   */

  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content]));
  a.download = filename;
  a.click();
}

async function copyClipboard(text: string) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return await navigator.clipboard.writeText(text);
  }

  const el = document.createElement("textarea");
  el.value = text;
  // android may require editable
  el.style.position = "absolute";
  el.style.left = "-9999px";
  document.body.appendChild(el);
  el.focus();
  el.select();
  el.setSelectionRange(0, text.length);
  document.execCommand("copy");
  document.body.removeChild(el);
}

export function useClipboard() {
  /**
   * Use clipboard
   * @example
   * const copy = useClipboard();
   * copy("Hello world!");
   */
  const { t } = useTranslation();

  return async (text: string) => {
    try {
      await copyClipboard(text);
      toast.success(t("toast.copied"));
    } catch (e) {
      console.error(e);

      const err = e as Error;
      toast.error(t("toast.copy_failed", { message: err.message }));
    }
  };
}

export function useSaver() {
  const { t } = useTranslation();

  return (filename: string, content: string) => {
    try {
      saveAsFile(filename, content);
      toast.success(t("toast.saved"));
    } catch (e) {
      console.error(e);

      toast.error(t("toast.save_failed", { message: toErrorMessage(e) }));
    }
  };
}

export function toSearchURI(query: string | undefined | null) {
  if (!query) return "/";
  const q = query.trim();
  return q ? `/${encodeURIComponent(q)}` : "/";
}

export function includeArgs(from: string, ...args: string[]): boolean {
  return args.some((arg) => from.toLowerCase().includes(arg.toLowerCase()));
}

export function toErrorMessage(e: any): string {
  return e.message || "Unknown error";
}

export function extractDomain(url: string): string | null {
  try {
    const result = parse(getSpecialDomain(url), {
      allowPrivateDomains: false,
    });

    return result.domain ?? null;
  } catch {
    return null;
  }
}

export function stripUrlToHostname(input: string): string {
  let s = input.trim();
  // Strip full protocol (scheme://)
  s = s.replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//i, "");
  // Strip partial protocol artifacts: "https:/" or "https:" left over after single-slash URLs
  s = s.replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/?/i, "");
  // Strip any leading slashes remaining
  s = s.replace(/^\/+/, "");
  const slashIdx = s.indexOf("/");
  if (slashIdx !== -1) s = s.substring(0, slashIdx);
  const qIdx = s.indexOf("?");
  if (qIdx !== -1) s = s.substring(0, qIdx);
  const atIdx = s.indexOf("@");
  if (atIdx !== -1) s = s.substring(atIdx + 1);
  const lastColon = s.lastIndexOf(":");
  if (lastColon > 0 && s.indexOf(".", lastColon) === -1) {
    s = s.substring(0, lastColon);
  }
  return s;
}

/**
 * Sanitise raw search input: strip protocol, path, port, auth — leaving only
 * the hostname / domain / IP portion. Does NOT validate; call
 * validateAndSanitizeInput for full validation.
 */
export function sanitizeInput(raw: string): string {
  let s = raw.trim();
  // 0. Remove all whitespace (e.g. "x .com" → "x.com", "https:// x.com" → "https://x.com")
  s = s.replace(/\s+/g, "");
  // 1. Strip full protocol (https://, http://, ftp://, //, …)
  s = s.replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//i, "");
  s = s.replace(/^\/\//, "");
  // 2. Strip partial protocol artifacts left by single-slash URLs (https:/X)
  s = s.replace(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/?/i, "");
  // 3. Strip leading slashes
  s = s.replace(/^\/+/, "");
  // 4. Truncate at first path / query / fragment separator
  const sepIdx = s.search(/[/?#]/);
  if (sepIdx !== -1) s = s.substring(0, sepIdx);
  // 5. Strip port number (e.g. example.com:8080)
  const colonIdx = s.lastIndexOf(":");
  if (colonIdx > 0 && /^\d+$/.test(s.substring(colonIdx + 1))) {
    s = s.substring(0, colonIdx);
  }
  // 6. Strip auth prefix (user:pass@host → host)
  const atIdx = s.indexOf("@");
  if (atIdx !== -1 && atIdx < s.length - 1) s = s.substring(atIdx + 1);
  // 7. Remove characters that are never valid in a domain, IP, or ASN.
  //    Covers common typos like "w,.com" → "w.com", "w;.com" → "w.com".
  //    Preserves: letters, digits, dot, hyphen, colon (IPv6), brackets (IPv6
  //    literal), plus non-ASCII bytes (IDN / unicode domains).
  s = s.replace(/[,;`'"!$%^&*()+=<>{}|\\~]/g, "");
  // 8. Collapse consecutive dots and strip leading/trailing dots.
  //    e.g. "..com" → "com", "w..com" → "w.com", "w.com." → "w.com"
  s = s.replace(/\.{2,}/g, ".");
  s = s.replace(/^\.+/, "").replace(/\.+$/, "");
  return s.trim();
}

export type SearchValidationResult = {
  valid: boolean;
  cleaned: string;
  errorKey?: string;
  errorArgs?: Record<string, string>;
  /** true = show as amber warning but still allow the search to proceed */
  isWarning?: boolean;
};

/**
 * Clean raw user input then validate it.
 * Strategy: be lenient — clean first, validate after.
 * Returns { valid, cleaned } on success or { valid: false, errorKey } on failure.
 */
const MAX_VALIDATED_LENGTH = 300;

export function validateAndSanitizeInput(raw: string): SearchValidationResult {
  const cleaned = sanitizeInput(raw);

  if (!cleaned) {
    return { valid: false, cleaned: "", errorKey: "validation.empty" };
  }

  // Universal length guard (matches the server-side MAX_QUERY_LENGTH = 300)
  if (cleaned.length > MAX_VALIDATED_LENGTH) {
    return { valid: false, cleaned, errorKey: "validation.too_long", errorArgs: { max: String(MAX_VALIDATED_LENGTH) } };
  }

  // ASN
  if (/^AS\d+$/i.test(cleaned)) return { valid: true, cleaned };

  // IPv4 CIDR
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(cleaned)) return { valid: true, cleaned };

  // IPv6 CIDR
  if (/^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\/\d{1,3}$/.test(cleaned)) return { valid: true, cleaned };

  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleaned)) return { valid: true, cleaned };

  // IPv6
  if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(cleaned)) return { valid: true, cleaned };

  // ── Domain validation ──────────────────────────────────────────────────────

  // Must contain at least one dot
  if (!cleaned.includes(".")) {
    return { valid: false, cleaned, errorKey: "validation.no_dot" };
  }

  // Total length limit per RFC 1035
  if (cleaned.length > 253) {
    return { valid: false, cleaned, errorKey: "validation.too_long" };
  }

  const labels = cleaned.split(".");

  for (const label of labels) {
    if (label.length === 0) {
      return { valid: false, cleaned, errorKey: "validation.invalid_domain" };
    }
    if (label.length > 63) {
      return { valid: false, cleaned, errorKey: "validation.label_too_long" };
    }
    // For ASCII labels, enforce valid characters and hyphen placement
    const isAscii = !/[^\x00-\x7F]/.test(label);
    if (isAscii) {
      if (!/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$/.test(label)) {
        return { valid: false, cleaned, errorKey: "validation.invalid_chars" };
      }
    }
    // Non-ASCII labels (IDN/unicode): pass through — lenient for internationalised domains
  }

  // TLD must be at least 2 characters
  const tld = labels[labels.length - 1];
  if (tld.length < 2) {
    return { valid: false, cleaned, errorKey: "validation.invalid_tld", errorArgs: { tld: `.${tld}` } };
  }

  // TLD must not be purely numeric — no real ICANN TLD consists only of digits
  // e.g. "555.55", "example.123" are not valid domains
  if (/^\d+$/.test(tld)) {
    return { valid: false, cleaned, errorKey: "validation.invalid_tld", errorArgs: { tld: `.${tld}` } };
  }

  // Validate TLD against the ICANN Public Suffix List via tldts
  // tldts always returns a publicSuffix, must check isIcann for real TLD
  const parsed = parse(cleaned, { allowPrivateDomains: false });
  const hasNonAsciiTld = /[^\x00-\x7F]/.test(tld); // IDN TLD — be lenient
  if (!parsed.isIcann && !hasNonAsciiTld) {
    // Soft warning: show the amber notice but still allow the search to proceed.
    // The WHOIS/RDAP server will give the authoritative answer if the TLD truly
    // doesn't exist, and this avoids false-blocking newly-delegated gTLDs that
    // haven't propagated to the tldts PSL snapshot yet.
    return {
      valid: true,
      cleaned,
      errorKey: "validation.unknown_tld",
      errorArgs: { tld: `.${tld}` },
      isWarning: true,
    };
  }

  return { valid: true, cleaned };
}

export function smartCleanDomain(input: string): string {
  const trimmed = input.trim();
  const hasProtocol = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(trimmed);
  const hasPath = !hasProtocol && trimmed.includes("/");

  if (!hasProtocol && !hasPath) {
    const parsed = parse(trimmed, { allowPrivateDomains: false });
    if (parsed.domain) return parsed.domain;
    return trimmed;
  }

  const hostname = stripUrlToHostname(trimmed);
  const parsed = parse(hostname, { allowPrivateDomains: false });
  if (parsed.domain) return parsed.domain;
  return hostname;
}

export function isLikelyUrl(input: string): boolean {
  const s = input.trim();
  return (
    /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(s) ||
    /^www\.[a-zA-Z0-9]/.test(s) ||
    (s.includes("/") && !s.startsWith("AS") && !/^[\d.:]+\//.test(s))
  );
}

export function extractDomainTld(domain: string): string {
  const parts = domain.split(".");
  return parts.length > 1 ? "." + parts[parts.length - 1] : "";
}

export function isValidDomainTld(domain: string): boolean {
  if (!domain.includes(".")) return true;
  if (/^AS\d+$/i.test(domain)) return true;
  if (/^[\d.:/]+$/.test(domain)) return true;
  if (/^([0-9a-fA-F]{0,4}:){1,7}/.test(domain)) return true;
  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  if (tld.length < 2) return true;
  const hasNonAsciiTld = /[^\x00-\x7F]/.test(tld); // IDN TLD — be lenient
  if (hasNonAsciiTld) return true;
  const parsed = parse(domain, { allowPrivateDomains: false });
  return parsed.isIcann === true;
}

export function cleanDomain(domain: string): string {
  const ipv4CidrMatch = domain.match(/^((\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/);
  if (ipv4CidrMatch) {
    return ipv4CidrMatch[0];
  }

  const ipv6CidrMatch = domain.match(
    /^(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})\/(\d{1,3})$/,
  );
  if (ipv6CidrMatch) {
    return ipv6CidrMatch[0];
  }

  const ipMatch = domain.match(
    /^(https?:\/\/)?((\d{1,3}\.){3}\d{1,3})(:\d+)?(\/.*)?$/,
  );
  if (ipMatch) {
    return ipMatch[2];
  }

  const hasProtocol = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(domain);
  const hasPath = !hasProtocol && domain.includes("/");

  if (hasProtocol || hasPath) {
    const hostname = stripUrlToHostname(domain);
    const parsed = parse(hostname, { allowPrivateDomains: false });
    if (parsed.domain) return parsed.domain;
    const fallback = extractDomain(hostname);
    if (fallback) return fallback;
    return hostname;
  }

  const hostname = extractDomain(domain);
  if (hostname) {
    return hostname;
  }

  return domain;
}

export function getWindowHref(): string {
  // if in server side, return empty string
  if (typeof window === "undefined") return "";

  return window.location.href;
}

const STATIC_PAGE_PREFIXES = [
  "/", "/docs", "/tools", "/directory", "/tlds", "/whois-servers",
  "/stamp", "/remind", "/api",
  "/login", "/register", "/dashboard",
  "/dns", "/ssl", "/ip", "/icp", "/http",
  "/about", "/sponsor", "/links", "/changelog",
  "/admin", "/feedback",
  "/og-card", "/404", "/500",
  "/guide", "/nav", "/payment",
  "/forgot-password", "/reset-password", "/sitemap",
  "/faq", "/privacy", "/terms",
];

/**
 * Returns true only when `url` is a WHOIS/RDAP search result route,
 * i.e. it does NOT match any known static page prefix.
 * Used by both the home page and the [...query] results page to decide
 * whether a routeChangeStart should show a loading spinner on the search button.
 */
export function isSearchRoute(url: string): boolean {
  const clean = url.split("?")[0].replace(/^\/(en|zh|zh-tw|de|ru|ja|fr|ko)(\/|$)/, "/");
  return !STATIC_PAGE_PREFIXES.some((p) => clean === p || clean.startsWith(p + "/"));
}

export const CURRENCY_SYMBOL: Record<string, string> = {
  CNY: "¥", USD: "$", EUR: "€", HKD: "HK$", GBP: "£", JPY: "¥",
};
