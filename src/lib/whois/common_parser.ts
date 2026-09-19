/**
 * WHOIS text analysis — main entry point.
 *
 * The heavy-lifting helpers have been extracted into focused sub-modules:
 *   parsers/utils.ts          — string / field helpers
 *   parsers/date.ts           — date-format parsing and domain-age computation
 *   parsers/preprocessors.ts  — per-TLD raw-text normalisation
 *   parsers/status-injection.ts — synthetic status detection from free-form text
 *
 * This file re-exports the public API and wires the sub-modules together
 * inside the main analyzeWhois() dispatcher.
 */

import {
  DomainStatusProps,
  initialWhoisAnalyzeResult,
  WhoisAnalyzeResult,
} from "@/lib/whois/types";
import { includeArgs } from "@/lib/utils";
import {
  isDomainLike,
  convertIdnToUnicode,
  cleanFieldValue,
  isRedactedValue,
} from "@/lib/whois/parsers/utils";
import {
  analyzeTime,
  extractDateNearKeyword,
  applyParams,
} from "@/lib/whois/parsers/date";
import {
  preprocessSmWhois,
  preprocessIslandNetworks,
} from "@/lib/whois/parsers/preprocessors";
import { injectSyntheticStatuses } from "@/lib/whois/parsers/status-injection";
import { LABEL_ALIASES } from "@/lib/whois/parsers/field-labels";
import {
  ExtractContext,
  FIELD_EXTRACTORS,
} from "@/lib/whois/parsers/field-extractors";
import {
  splitWhoisLine,
  stripNetworkPrefix,
} from "@/lib/whois/parsers/line-tokenizer";

// Re-export for backward compatibility (rdap_client.ts and others import this).
export { applyParams };

/**
 * Detect explicit privacy-protection markers in WHOIS/RDAP text.
 *
 * Only exact, well-known proxy markers count — "privacy" appearing in a
 * registrar name ("Namecheap, Inc.") or a random sentence must NOT set the
 * flag. The matcher looks for standalone proxy-brand tokens or the canonical
 * ICANN "Withheld for Privacy Purposes" phrase.
 */
const PRIVACY_PROXY_PATTERNS: RegExp[] = [
  /\bwithheld for privacy\b/i,
  // Explicit proxy brands / service phrasing — "privacy service" alone is too
  // broad (a registrar named "Privacy Services LLC" must NOT match), so we
  // require either a well-known brand token or the "provided by" construction.
  /\bwhoisguard\b/i,
  /\bdomains by proxy\b/i,
  /\bprivacy(?:-)?guard\b/i,
  /\bprivacy(?:-)?protect(?:ion)?\b/i,
  /\bperfect privacy\b/i,
  /\bprivacy protector\b/i,
  /\bprivacy shield\b/i,
  /\bprivacy services? provided by\b/i,
  /\bprivacy(?:-)?proxy\b/i,
  /\bprivacy(?:-)?service\s+of\s+/i,
  /\bdomain (?:privacy|protection)\b/i,
  // Chinese ccTLD privacy-proxy labels
  /隐私保护/,
  /隐私服务/,
  // Russian privacy phrasing
  /скрыто для конфиденциальности/i,
];

export function detectPrivacyProxy(text: string): boolean {
  if (!text) return false;
  return PRIVACY_PROXY_PATTERNS.some((re) => re.test(text));
}

/**
 * Labels that contain "registrar" but are NOT the registrar's name.
 *
 * The fallback registrar extraction below uses substring matching
 * (includeArgs(key, "registrar")), so any key carrying "registrar" was
 * previously eligible. Contact/support/organisation fields slipped through
 * and produced values such as "support@reg.example" or "John Doe" as the
 * registrar. Each token here is checked as a substring of the key; if any
 * matches, the fallback is suppressed for that line.
 */
const REGISTRAR_KEY_EXCLUSIONS: readonly string[] = [
  "service",
  "support",
  "contact",
  "address",
  "postal",
  "phone",
  "tel",
  "fax",
  "email",
  "e-mail",
  "url",
  "website",
  "whois",
  "iana",
  "server",
  "abuse",
  "registration",
  "expir",
  "date",
  "status",
  "handle",
  "id",
  "dnssec",
];

function isRegistrarNameKey(key: string): boolean {
  if (!includeArgs(key, "registrar")) return false;
  return !REGISTRAR_KEY_EXCLUSIONS.some((token) => includeArgs(key, token));
}

export async function analyzeWhois(data: string): Promise<WhoisAnalyzeResult> {
  data = preprocessSmWhois(data);
  data = preprocessIslandNetworks(data);

  const lines = data
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const result: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    status: [],
    nameServers: [],
    rawWhoisContent: data,
  };

  const ctx: ExtractContext = {
    explicitUnicodeDomain: "",
    explicitAsciiDomain: "",
  };
  // JPRS English format wraps multi-line values: "[Postal Address]" followed by
  // indented continuation lines without a key or colon. Only "postal address"
  // opts in — keeps the continuation logic narrowly scoped to JPRS layouts.
  let multilineAddressTarget = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    let key: string;
    let value: string;

    const bracketMatch = line.match(/^(?:[a-z]\.\s*)?\[(.+?)\]\s+(.+)/);
    if (bracketMatch) {
      key = bracketMatch[1].trim().toLowerCase();
      value = cleanFieldValue(bracketMatch[2].trim());
      multilineAddressTarget =
        key === "postal address" && result.registrantAddress === "Unknown";
    } else {
      // Continuation of a JPRS "[Postal Address]" block. Lines are pre-trimmed,
      // so indentation is gone — a continuation is any line with no bracket
      // header and no "key: value" colon separator directly following the block.
      if (
        multilineAddressTarget &&
        !line.startsWith("[") &&
        !line.includes(":")
      ) {
        const cont = cleanFieldValue(line);
        if (cont) {
          result.registrantAddress += ", " + cont;
          continue;
        }
      }
      multilineAddressTarget = false;
      // Shared line-splitting primitives (parsers/line-tokenizer.ts): the
      // first-colon boundary and the "Network:" prefix stripping that some
      // registries emit are the same rules parseSimpleWhoisLines uses, so the
      // two parsers stay in sync.
      const pair = splitWhoisLine(stripNetworkPrefix(line));
      if (!pair) continue;
      key = pair.key.toLowerCase();
      // Nordic registries (.fi Traficom, .no NORID) pad keys with dots for
      // column alignment: "domain.............: nic.fi". Strip the trailing
      // dot run so the key matches the regular case labels.
      key = key.replace(/\.+$/, "");
      value = cleanFieldValue(pair.value);
    }

    if (!value) continue;

    const fieldKey = LABEL_ALIASES[key] ?? key;
    const extractor = FIELD_EXTRACTORS[fieldKey];
    if (extractor) {
      extractor(value, result, ctx);
    }

    if (
      includeArgs(key, "domain name") &&
      !result.domain &&
      isDomainLike(value)
    ) {
      result.domain = value;
    } else if (isRegistrarNameKey(key) && result.registrar === "Unknown") {
      result.registrar = value;
    } else if (
      includeArgs(key, "admin", "administrative") &&
      includeArgs(key, "email", "e-mail", "mail") &&
      result.adminEmail === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.adminEmail = value;
    } else if (
      includeArgs(key, "admin", "administrative") &&
      includeArgs(key, "phone", "tel") &&
      result.adminPhone === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.adminPhone = value.replace(/^tel:/i, "").trim();
    } else if (
      includeArgs(key, "tech", "technical") &&
      includeArgs(key, "email", "e-mail", "mail") &&
      result.techEmail === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.techEmail = value;
    } else if (
      includeArgs(key, "tech", "technical") &&
      includeArgs(key, "phone", "tel") &&
      result.techPhone === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.techPhone = value.replace(/^tel:/i, "").trim();
    } else if (
      includeArgs(key, "contact email") &&
      result.registrantEmail === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.registrantEmail = value;
    } else if (
      includeArgs(key, "contact phone") &&
      result.registrantPhone === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.registrantPhone = value;
    } else if (
      includeArgs(
        key,
        "creation",
        "created",
        "created date",
        "registration time",
        "registered",
        "commencement",
      ) &&
      result.creationDate === "Unknown"
    ) {
      result.creationDate = analyzeTime(value);
    } else if (
      includeArgs(key, "expiration", "expiry", "expire", "expire date") &&
      result.expirationDate === "Unknown"
    ) {
      result.expirationDate = analyzeTime(value);
    } else if (
      includeArgs(
        key,
        "updated",
        "update",
        "last update",
        "last updated",
        "last-modified",
      ) &&
      result.updatedDate === "Unknown"
    ) {
      result.updatedDate = analyzeTime(value);
    } else if (
      includeArgs(key, "account name", "registrant org") &&
      result.registrantOrganization === "Unknown" &&
      !isRedactedValue(value)
    ) {
      result.registrantOrganization = value;
    }
  }

  // Deduplicate status codes
  let newStatus: DomainStatusProps[] = [];
  for (let i = 0; i < result.status.length; i++) {
    const status = result.status[i];
    if (newStatus.find((item) => item.status === status.status)) continue;
    newStatus.push(status);
  }
  result.status = newStatus;

  // Detect synthetic statuses from free-form WHOIS text (reserved, premium,
  // prohibited, suspended) — see parsers/status-injection.ts for full details.
  injectSyntheticStatuses(data, result);

  // Detect registrant privacy-protection markers (WhoisGuard, PrivacyGuard,
  // Withheld for Privacy, etc.). When a privacy proxy is explicitly named in
  // the WHOIS body, contact fields are almost certainly proxied — flag it so
  // the UI can avoid presenting them as the real registrant. Only explicit
  // markers count; a bare email address is never treated as privacy evidence.
  if (detectPrivacyProxy(data)) {
    result.registrantPrivacy = true;
  }

  // Deduplicate nameservers
  const seenNS = new Set<string>();
  result.nameServers = result.nameServers.filter((ns) => {
    const nsKey = ns.toLowerCase().trim();
    if (!nsKey || seenNS.has(nsKey)) return false;
    seenNS.add(nsKey);
    return true;
  });

  // Date fallback: scan raw text for dates near known date keywords when the
  // structured fields were not populated by the switch above.
  if (result.creationDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "creat",
      "registered",
      "activation",
      "anniversary",
      "inception",
      "enregistr",
      "registro",
      "criado",
    ]);
    if (fallback) result.creationDate = fallback;
  }

  if (result.expirationDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "expir",
      "valid until",
      "paid-till",
      "paid till",
      "renewal",
      "due date",
      "venc",
      "ablauf",
      "validade",
    ]);
    if (fallback) result.expirationDate = fallback;
  }

  if (result.updatedDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "updated",
      "modified",
      "last change",
      "last update",
      "mise à jour",
      "mise a jour",
      "modificat",
      "actualiz",
    ]);
    if (fallback) result.updatedDate = fallback;
  }

  // IDN conversion: if the WHOIS body explicitly declared a Unicode domain
  // name, use that; otherwise try to detect ACE labels in result.domain and
  // convert to Unicode for display.
  if (ctx.explicitUnicodeDomain) {
    result.domain = ctx.explicitUnicodeDomain;
    if (ctx.explicitAsciiDomain) {
      result.domainPunycode = ctx.explicitAsciiDomain.toUpperCase();
    } else if (result.domain) {
      const punycheck = convertIdnToUnicode(result.domain);
      if (punycheck.punycode) result.domainPunycode = punycheck.punycode;
    }
  } else if (result.domain) {
    const converted = convertIdnToUnicode(result.domain);
    if (converted.punycode) {
      result.domainPunycode = converted.punycode;
      result.domain = converted.unicode;
    }
  }

  return await applyParams(result);
}
