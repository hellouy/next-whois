/**
 * Shared utility helpers for WHOIS field parsing.
 *
 * Extracted from common_parser.ts to keep each concern in its own module:
 *   utils.ts        — string / field helpers (this file)
 *   date.ts         — date-format parsing
 *   preprocessors.ts — per-TLD raw-text normalisation
 *   status-injection.ts — synthetic status detection from free-form text
 */

import { DomainStatusProps } from "@/lib/whois/types";
import { domainToUnicode } from "url";

// ── Domain-string helpers ────────────────────────────────────────────────────

/** Returns true if the value looks like an actual domain name rather than policy/legal text. */
export function isDomainLike(value: string): boolean {
  if (!value || value.length > 255) return false;
  if (/\s/.test(value)) return false;
  if (!value.includes(".")) return false;
  return true;
}

export function convertIdnToUnicode(domain: string): {
  unicode: string;
  punycode?: string;
} {
  try {
    const hasAceLabel = domain
      .toLowerCase()
      .split(".")
      .some((label) => label.startsWith("xn--"));
    if (!hasAceLabel) return { unicode: domain };
    const unicode = domainToUnicode(domain.toLowerCase());
    if (unicode && unicode !== domain.toLowerCase()) {
      return { unicode, punycode: domain.toUpperCase() };
    }
    return { unicode: domain };
  } catch {
    return { unicode: domain };
  }
}

// ── HTML entity decoding ─────────────────────────────────────────────────────

const HTML_ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&apos;": "'",
  "&nbsp;": " ",
  "&eacute;": "é",
  "&Eacute;": "É",
  "&egrave;": "è",
  "&Egrave;": "È",
  "&ecirc;": "ê",
  "&Ecirc;": "Ê",
  "&euml;": "ë",
  "&aacute;": "á",
  "&Aacute;": "Á",
  "&agrave;": "à",
  "&Agrave;": "À",
  "&acirc;": "â",
  "&Acirc;": "Â",
  "&auml;": "ä",
  "&Auml;": "Ä",
  "&aring;": "å",
  "&Aring;": "Å",
  "&oacute;": "ó",
  "&Oacute;": "Ó",
  "&ograve;": "ò",
  "&ocirc;": "ô",
  "&ouml;": "ö",
  "&Ouml;": "Ö",
  "&uacute;": "ú",
  "&ugrave;": "ù",
  "&uuml;": "ü",
  "&Uuml;": "Ü",
  "&iacute;": "í",
  "&igrave;": "ì",
  "&icirc;": "î",
  "&iuml;": "ï",
  "&ccedil;": "ç",
  "&Ccedil;": "Ç",
  "&ntilde;": "ñ",
  "&Ntilde;": "Ñ",
  "&szlig;": "ß",
  "&aelig;": "æ",
  "&AElig;": "Æ",
  "&oslash;": "ø",
  "&Oslash;": "Ø",
  "&eth;": "ð",
  "&thorn;": "þ",
  "&laquo;": "«",
  "&raquo;": "»",
  "&copy;": "©",
  "&reg;": "®",
  "&trade;": "™",
  "&mdash;": "—",
  "&ndash;": "–",
  "&hellip;": "…",
};

export function decodeHtmlEntities(str: string): string {
  if (!str || !str.includes("&")) return str;
  let result = str;
  for (const [entity, char] of Object.entries(HTML_ENTITIES)) {
    result = result.split(entity).join(char);
  }
  result = result.replace(/&#(\d+);/g, (_, code) =>
    String.fromCharCode(parseInt(code, 10)),
  );
  result = result.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16)),
  );
  return result;
}

// ── Field-value cleaning ─────────────────────────────────────────────────────

export function cleanFieldValue(value: string): string {
  if (!value) return value;
  let cleaned = value.trim();
  cleaned = decodeHtmlEntities(cleaned);
  cleaned = cleaned.replace(/^[\s\u00a0\u2022\u00b7·\-]+/, "").trim();
  cleaned = cleaned.replace(/^\.{3,}\s*/, "").trim();
  return cleaned;
}

export function isRedactedValue(value: string): boolean {
  if (!value) return false;
  const dotRatio = (value.match(/\./g) || []).length / value.length;
  if (dotRatio > 0.5 && value.length > 5) return true;
  if (/^[.\s]+$/.test(value)) return true;
  if (/REDACTED|WITHHELD|PRIVACY|NOT DISCLOSED/i.test(value)) return true;
  // .tg (NICTogo JWhoisServer) redacts every contact field with "[PRIVEE]".
  if (/^\[?PRIVEE\]?$/i.test(value)) return true;

  // Registry placeholder / instructional text that is NOT a real field value.
  // Some registries (e.g. .in via RDDS) replace contact email/postal with a
  // full sentence telling you to query the Registrar of Record instead.
  // These are privacy redactions just like "REDACTED FOR PRIVACY" and must
  // not leak into the contact fields or the raw display.
  if (
    /RDDS service|Registrar of Record|Please query|queried domain name/i.test(
      value,
    )
  ) {
    return true;
  }
  // A "value" that is really a long instructional sentence (no phone/email/
  // code/date signature) is placeholder boilerplate, not data.
  if (
    value.length > 80 &&
    /[a-z]{4,}/i.test(value) &&
    !/[+@]/.test(value) &&
    !/\d{2,}[-.\s]\d{2,}/.test(value)
  ) {
    return true;
  }
  // A value containing a "mailto:" URI (URL-encoded or not) is a link to a
  // form, not the contact data itself.
  if (/\(?mailto:/i.test(value)) return true;
  return false;
}

/**
 * True when the value looks like a genuine email address. Used to guard
 * contact-email fields: some registries substitute instructional prose or a
 * URL where the address should be, which isRedactedValue() may not catch.
 */
export function isEmailLike(value: string): boolean {
  if (!value) return false;
  // "Select Request Email Form at https://..." → has @ in the domain part but
  // is a sentence, not an address. Require a bare addr-spec: text@text.text.
  const bare = value.trim().replace(/^<?/, "").replace(/>?$/, "");
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(bare);
}

// ── Status helpers ───────────────────────────────────────────────────────────

export function analyzeDomainStatus(status: string): DomainStatusProps {
  const cleaned = cleanFieldValue(status);
  const segments = cleaned.split(" ");
  let url = segments.slice(1).join(" ");
  url.startsWith("(") && url.endsWith(")") && (url = url.slice(1, -1));
  return { status: segments[0], url };
}
