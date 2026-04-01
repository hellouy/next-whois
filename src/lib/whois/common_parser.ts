import {
  DomainStatusProps,
  initialWhoisAnalyzeResult,
  WhoisAnalyzeResult,
} from "@/lib/whois/types";
import { includeArgs } from "@/lib/utils";
import moment from "moment";
import { domainToUnicode } from "url";
import { getDomainPricing, getDomainTransferNegotiable } from "@/lib/pricing/client";

/** Returns true if the value looks like an actual domain name rather than a policy/legal text. */
function isDomainLike(value: string): boolean {
  if (!value || value.length > 255) return false;
  if (/\s/.test(value)) return false; // domain names have no spaces
  if (!value.includes(".")) return false; // must have a TLD
  return true;
}

function convertIdnToUnicode(domain: string): {
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

function decodeHtmlEntities(str: string): string {
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

function cleanFieldValue(value: string): string {
  if (!value) return value;
  let cleaned = value.trim();
  cleaned = decodeHtmlEntities(cleaned);
  cleaned = cleaned.replace(/^[\s\u00a0\u2022\u00b7·\-]+/, "").trim();
  cleaned = cleaned.replace(/^\.{3,}\s*/, "").trim();
  return cleaned;
}

function isRedactedValue(value: string): boolean {
  if (!value) return false;
  const dotRatio = (value.match(/\./g) || []).length / value.length;
  if (dotRatio > 0.5 && value.length > 5) return true;
  if (/^[.\s]+$/.test(value)) return true;
  if (/REDACTED|WITHHELD|PRIVACY|NOT DISCLOSED/i.test(value)) return true;
  return false;
}

function analyzeDomainStatus(status: string): DomainStatusProps {
  const cleaned = cleanFieldValue(status);
  const segments = cleaned.split(" ");
  let url = segments.slice(1).join(" ");

  url.startsWith("(") && url.endsWith(")") && (url = url.slice(1, -1));
  return {
    status: segments[0],
    url,
  };
}

const DATE_FORMATS = [
  "YYYY-MM-DDTHH:mm:ssZ",
  "YYYY-MM-DDTHH:mm:ss.SSSZ",
  "YYYY-MM-DDTHH:mm:ssZZ",
  "YYYY-MM-DD HH:mm:ss",
  "YYYY-MM-DD HH:mm:ssZ",
  "YYYY-MM-DD",
  "DD.MM.YYYY HH:mm:ss",
  "DD.MM.YYYY HH:mm",
  "DD.MM.YYYY",
  "DD-MM-YYYY HH:mm:ss",
  "DD-MM-YYYY",
  "MM/DD/YYYY HH:mm:ss",
  "MM/DD/YYYY",
  "YYYY/MM/DD HH:mm:ss",
  "YYYY/MM/DD",
  "YYYY.MM.DD HH:mm:ss",
  "YYYY.MM.DD",
  "DD MMM YYYY",
  "DD-MMM-YYYY",
  "MMM DD YYYY",
  "MMM DD, YYYY",
  "D-MMM-YYYY",
  "YYYYMMDD",
  "YYYY-MM-DDTHH:mm:ss.SSS[Z]",
  "ddd MMM DD HH:mm:ss [UTC] YYYY",
  "ddd, DD MMM YYYY HH:mm:ss ZZ",
  "DD/MM/YYYY HH:mm:ss",
  "DD/MM/YYYY",
  "D MMM YYYY",
  "D MMMM YYYY HH:mm:ss",
  "D MMMM YYYY HH:mm",
  "D MMMM YYYY",
  "YYYY-MM-DD HH:mm:ss UTC",
  "YYYY-MM-DDZ",
  "MM-DD-YYYY",
  "YYYY MM DD",
  "D/M/YYYY",
  "D.M.YYYY",
];

const DATE_REGEX = /\b(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)?|\d{2}[.\/\-]\d{2}[.\/\-]\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?)?|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4}|\d{4}[.\/]\d{2}[.\/]\d{2})\b/i;

function extractDateNearKeyword(raw: string, keywords: string[]): string {
  const lines = raw.split("\n");
  for (const line of lines) {
    const lower = line.toLowerCase();
    const hasKeyword = keywords.some((kw) => lower.includes(kw));
    if (!hasKeyword) continue;
    const m = line.match(DATE_REGEX);
    if (m) {
      const parsed = analyzeTime(m[1]);
      if (parsed && parsed !== m[1]) return parsed;
    }
  }
  return "";
}

function analyzeTime(time: string): string {
  if (!time || time.length === 0) return time;

  try {
    let cleaned = time
      .replace(/<|>/g, "")
      .replace(/\[.*?\]/g, "")
      .trim();

    const beforePrefix = cleaned.match(/^before\s+(.+)$/i);
    if (beforePrefix) cleaned = beforePrefix[1].trim();

    const parenMatch = cleaned.match(/^(.+?)\s*\(.*?\)\s*$/);
    if (parenMatch) cleaned = parenMatch[1].trim();

    const m = moment(cleaned, DATE_FORMATS, true);
    if (m.isValid()) return m.toISOString();

    const mLenient = moment(cleaned, DATE_FORMATS, false);
    if (mLenient.isValid()) return mLenient.toISOString();

    const native = new Date(cleaned);
    if (!isNaN(native.getTime())) return native.toISOString();

    return time;
  } catch (e) {
    return time;
  }
}

function calculateDomainAge(creationDate: string): number {
  if (creationDate === "Unknown") return 0;

  const created = moment(creationDate);
  const now = moment();

  return now.diff(created, "years");
}

function calculateRemainingDays(expirationDate: string): number {
  if (expirationDate === "Unknown") return 0;

  const expiry = moment(expirationDate);
  const now = moment();

  return Math.max(0, expiry.diff(now, "days"));
}

export async function applyParams(result: WhoisAnalyzeResult) {
  // Calculate domain age and remaining days
  result.domainAge =
    !result.creationDate || result.creationDate === "Unknown"
      ? null
      : calculateDomainAge(result.creationDate);
  result.remainingDays =
    !result.expirationDate || result.expirationDate === "Unknown"
      ? null
      : calculateRemainingDays(result.expirationDate);

  const [registerPrice, renewPrice, negotiable] = await Promise.all([
    getDomainPricing(result.domain, "new"),
    getDomainPricing(result.domain, "renew"),
    getDomainTransferNegotiable(result.domain),
  ]);
  result.registerPrice = registerPrice;
  result.renewPrice = renewPrice;
  result.negotiable = negotiable;

  return result;
}

/**
 * Normalises .sm (San Marino) WHOIS output into standard key: value lines.
 *
 * .sm WHOIS uses block-style contact sections:
 *   Owner:
 *   Junpeng Niu          ← name on next line
 *   Chang'An Street 66th ← address (no key prefix)
 *   100000 Beijing
 *   CN                   ← 2-letter country code
 *   Phone: +86 ...       ← sub-fields with colon are passed through
 *   Email: ...
 *
 *   DNS Servers:
 *   ns1.example.com      ← nameservers, one per line
 */
function preprocessSmWhois(data: string): string {
  // Detect .sm format: "DNS Servers:" alone on a line (no value after colon)
  if (!/^DNS Servers:\s*$/m.test(data) && !/^Owner:\s*$/m.test(data)) return data;

  const lines = data.split("\n");
  const out: string[] = [];
  // Which block we are currently inside
  let block: "owner" | "tech" | "dns" | null = null;
  let blockLine = 0; // lines consumed inside current block

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();

    // Blank line → reset block
    if (!t) {
      block = null;
      blockLine = 0;
      out.push("");
      continue;
    }

    // Detect block headers (nothing after the colon)
    if (/^Owner:\s*$/.test(t))            { block = "owner"; blockLine = 0; continue; }
    if (/^Technical Contact:\s*$/.test(t)) { block = "tech";  blockLine = 0; continue; }
    if (/^Administrative Contact:\s*$/.test(t)) { block = "tech"; blockLine = 0; continue; }
    if (/^DNS Servers?:\s*$/.test(t))    { block = "dns";   blockLine = 0; continue; }

    if (block === "dns") {
      // Each non-blank line is a nameserver hostname
      if (t.includes(".")) out.push(`Nameserver: ${t}`);
      continue;
    }

    if (block === "owner" || block === "tech") {
      // Lines that already contain a colon (Phone:, Email:, Fax:) — pass through as-is
      const colonIdx = t.indexOf(":");
      if (colonIdx > 0 && colonIdx < t.length - 1) {
        out.push(raw);
        blockLine++;
        continue;
      }

      // First content line → registrant/tech name
      if (blockLine === 0) {
        out.push(block === "owner"
          ? `Registrant Name: ${t}`
          : `Tech Name: ${t}`);
        blockLine++;
        continue;
      }

      // 2-letter country code
      if (/^[A-Z]{2}$/.test(t) && block === "owner") {
        out.push(`Registrant Country: ${t}`);
        blockLine++;
        continue;
      }

      // Street / postal lines — emit as registrant street (first one only)
      if (block === "owner" && blockLine === 1) {
        out.push(`Registrant Street: ${t}`);
      }
      blockLine++;
      continue;
    }

    // Not in any block — pass through unchanged
    out.push(raw);
  }

  return out.join("\n");
}

/**
 * Normalises Island Networks (.gg / .je) WHOIS output into standard key: value lines.
 *
 * Their format uses section headers (ending with ":") whose values appear on
 * the next indented line(s), and ordinal dates ("10th June 2018 at 05:02:34").
 */
function preprocessIslandNetworks(data: string): string {
  if (!data.includes("Island Networks") && !data.includes("channelisles.net")) return data;

  const rawLines = data.split("\n");
  const out: string[] = [];
  let lastSectionKey: string | null = null;

  for (let i = 0; i < rawLines.length; i++) {
    const trimmed = rawLines[i].trim();

    // Blank line resets section context
    if (!trimmed) {
      lastSectionKey = null;
      out.push("");
      continue;
    }

    // Section header: "Domain Status:" (ends with colon, nothing after)
    const sectionMatch = trimmed.match(/^([A-Za-z][^:]*?):\s*$/);
    if (sectionMatch) {
      lastSectionKey = sectionMatch[1].trim();
      continue; // don't emit yet — wait for value line
    }

    // Value line under a section header
    if (lastSectionKey) {
      // "Registered on DDth/st/nd/rd Month YYYY at HH:MM:SS"
      const ordinalMatch = trimmed.match(
        /^Registered on\s+(\d{1,2})(?:st|nd|rd|th)\s+(\w+)\s+(\d{4})(?:\s+at\s+(\d{2}:\d{2}:\d{2})(?:\.\d+)?)?/i,
      );
      if (ordinalMatch) {
        const [, day, month, year, time] = ordinalMatch;
        out.push(`Registered on: ${day} ${month} ${year}${time ? " " + time : ""}`);
        // keep lastSectionKey for any further value lines in this section
        continue;
      }

      // Generic value line → emit as "SectionKey: value"
      out.push(`${lastSectionKey}: ${trimmed}`);
      continue;
    }

    // Pass through any other line unchanged
    out.push(rawLines[i]);
  }

  return out.join("\n");
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

  let explicitUnicodeDomain = "";
  let explicitAsciiDomain = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    let key: string;
    let value: string;

    const bracketMatch = line.match(/^(?:[a-z]\.\s*)?\[(.+?)\]\s+(.+)/);
    if (bracketMatch) {
      key = bracketMatch[1].trim().toLowerCase();
      value = cleanFieldValue(bracketMatch[2].trim());
    } else {
      let segments = line.split(":");
      if (segments.length < 2) continue;
      if (segments.length >= 3 && segments[0].toLowerCase() === "network") {
        segments = segments.slice(1);
      }
      key = segments[0].trim().toLowerCase();
      value = cleanFieldValue(segments.slice(1).join(":").trim());
    }

    if (!value) continue;

    switch (key) {
      case "domain name (unicode)":
        if (!explicitUnicodeDomain) explicitUnicodeDomain = value;
        break;
      case "domain name (ascii)":
        if (!explicitAsciiDomain) explicitAsciiDomain = value;
        if (isDomainLike(value)) result.domain = result.domain || value;
        break;
      case "domain name":
      case "domain":
      case "nom de domaine":
      case "domaine":
        if (isDomainLike(value)) result.domain = result.domain || value;
        break;
      case "registrar":
      case "authorized agency":
      case "sponsoring registrar":
      case "registrar name":
      case "registrant registrar":
      case "registration service provider":
      case "enregistreur":
      case "bureau d'enregistrement":
        result.registrar = result.registrar === "Unknown" ? value : result.registrar;
        break;
      case "iana id":
        result.ianaId = value;
        break;
      case "registrar iana id":
        result.ianaId = value;
        break;
      case "whois server":
        result.whoisServer = value;
        break;
      case "whois":
        result.whoisServer = value;
        break;
      case "registrar whois server":
        result.whoisServer = value;
        break;
      case "updated date":
      case "last updated date":
      case "last modified":
      case "last-modified":
      case "modification date":
      case "modified":
      case "last update":
      case "last updated":
      case "update date":
      case "date updated":
      case "updated on":
      case "modified on":
      case "date de mise a jour":
      case "date de mise à jour":
      case "zuletzt geaendert am":
      case "updated (utc)":
      case "last-update":
      case "updated":
      case "last changed":
      case "changed on":
      case "modifié le":
      case "fecha de modificacion":
      case "actualizado":
      case "changed":
      case "last modification":
      case "modified date":
      case "last modified date":
      case "record last updated":
      case "record modified":
      case "last update date":
      case "domain updated":
      case "last-modified-date":
      case "senast ändrad":
      case "viimeksi muokattu":
      case "sist endret":
      case "sidst ændret":
      case "senest opdateret":
      case "letzte änderung":
      case "última modificación":
      case "última atualização":
        if (result.updatedDate === "Unknown") result.updatedDate = analyzeTime(value);
        break;
      case "creation date":
      case "registered date":
      case "activation":
      case "activation date":
      case "registered on":
      case "date registered":
      case "domain registered":
      case "created":
      case "created on":
      case "created date":
      case "registration date":
      case "registration time":
      case "date de creation":
      case "date de création":
      case "registriert am":
      case "datum registracije":
      case "created (utc)":
      case "created date (utc)":
      case "reg date":
      case "create date":
      case "entry created":
      case "domain registration date":
      case "first registered":
      case "first registration date":
      case "registered":
      case "register date":
      case "start date":
      case "date d'enregistrement":
      case "enregistré le":
      case "fecha de registro":
      case "fecha de creacion":
      case "fecha creacion":
      case "criado em":
      case "data de registro":
      case "anniversary":
      case "inception date":
      case "domain inception date":
      case "record created":
      case "created at":
      case "activation time":
      case "delegated on":
      case "delegated":
      case "fecha de alta":
      case "registreringsdatum":
      case "rekisteröintipäivä":
      case "registreringsdato":
      case "domainregistrierung":
        if (result.creationDate === "Unknown") result.creationDate = analyzeTime(value);
        break;
      case "domain name commencement date":
      case "domain commencement date":
        if (result.creationDate === "Unknown") result.creationDate = analyzeTime(value);
        break;
      case "expiration date":
      case "expiration":
      case "valid until":
      case "paid-till":
      case "paid till":
      case "expires on":
      case "expire date":
      case "expire":
      case "expires":
      case "expiry date":
      case "expiry":
      case "registry expiration date":
      case "date expiration":
      case "date d'expiration":
      case "ablaufdatum":
      case "expires (utc)":
      case "expiration date (utc)":
      case "expiration time":
      case "renewal date":
      case "due date":
      case "valid-date":
      case "expire-date":
      case "expiration-date":
      case "end date":
      case "domain expiration date":
      case "fecha de vencimiento":
      case "fecha expiracion":
      case "fecha de expiracion":
      case "validade":
      case "vence em":
      case "ablauf":
      case "laufzeit bis":
      case "registry expiry date":
      case "registrar registration expiration date":
      case "registration expiry date":
      case "expiration-date (registrar)":
      case "domain renewal date":
      case "renewal deadline":
      case "validity":
      case "validity date":
      case "valid through":
      case "valid to":
      case "valid-till":
      case "gyldig til":
      case "keston loppupäivä":
      case "giltig till":
      case "verfallsdatum":
        if (result.expirationDate === "Unknown") result.expirationDate = analyzeTime(value);
        break;
      case "state": {
        const expiryMatch = value.match(/\((\d{4}\/\d{2}\/\d{2})\)/);
        if (expiryMatch && result.expirationDate === "Unknown") {
          result.expirationDate = analyzeTime(expiryMatch[1]);
        }
        result.status.push(analyzeDomainStatus(value));
        break;
      }
      case "status":
      case "registration status":
        result.status.push(analyzeDomainStatus(value));
        break;
      case "domain status":
        result.status.push(analyzeDomainStatus(value));
        break;
      case "name server":
      case "name server (db)":
      case "host name":
      case "hostname":
      case "nameserver":
      case "ns":
      case "ns1":
      case "ns2":
      case "ns3":
      case "ns4":
      case "ns5":
      case "ns6":
      case "dns":
      case "dns1":
      case "dns2":
      case "dns3":
      case "dns4":
      case "primary nameserver":
      case "secondary nameserver":
      case "serveur dns":
      case "nameservers":
      case "name servers":
      case "nserver":
      case "p":
      // Split on commas (e.g. "ns1.foo.com, ns2.foo.com") then strip IPs
        for (const nsEntry of value.split(",")) {
          const ns = nsEntry.trim().split(/\s+/)[0];
          if (ns && ns.includes(".")) result.nameServers.push(ns);
        }
        break;
      // ── Registry domain ID ────────────────────────────────────────────────
      case "registry domain id":
      case "domain id":
      case "domain-id":
      case "roid":
        if (result.registryDomainId === "Unknown") result.registryDomainId = value;
        break;

      // ── Registrant name ────────────────────────────────────────────────────
      case "registrant name":
      case "registrant contact name":
      case "holder":
      case "owner":
        if (!isRedactedValue(value) && result.registrantName === "Unknown")
          result.registrantName = value;
        break;

      // ── Registrant organization ────────────────────────────────────────────
      case "registrant organization":
      case "registrant organisation":
      case "registrant org":
        if (!isRedactedValue(value)) result.registrantOrganization = value;
        break;
      case "organization":
      case "organisation":
      case "org-name":
        if (!isRedactedValue(value) && result.registrantOrganization === "Unknown")
          result.registrantOrganization = value;
        break;
      case "registrant":
        if (!isRedactedValue(value)) result.registrantOrganization = value;
        break;
      case "descr":
        if (
          !isRedactedValue(value) &&
          result.registrantOrganization === "Unknown"
        )
          result.registrantOrganization = value;
        break;

      // ── Registrant state/province ─────────────────────────────────────────
      case "registrant state/province":
      case "registrant state":
      case "registrant province":
      case "province":
        if (!isRedactedValue(value) && result.registrantProvince === "Unknown")
          result.registrantProvince = value;
        break;

      // ── Registrant city ────────────────────────────────────────────────────
      case "registrant city":
      case "registrant locality":
      case "city":
      case "locality":
        if (!isRedactedValue(value) && result.registrantCity === "Unknown")
          result.registrantCity = value;
        break;

      // ── Registrant street address ──────────────────────────────────────────
      case "registrant street":
      case "registrant address":
      case "registrant street1":
      case "registrant street2":
      case "registrant street3":
      case "street":
      case "address":
      case "addr":
        if (!isRedactedValue(value) && result.registrantAddress === "Unknown")
          result.registrantAddress = value;
        break;

      // ── Registrant postal code ─────────────────────────────────────────────
      case "registrant postal code":
      case "registrant zip":
      case "registrant zip code":
      case "postal code":
      case "zip code":
      case "zip":
      case "postcode":
      case "postalcode":
      case "postal-code":
        if (!isRedactedValue(value) && result.registrantPostalCode === "Unknown")
          result.registrantPostalCode = value;
        break;

      // ── Registrant country ────────────────────────────────────────────────
      case "registrant country":
      case "registrant country code":
      case "registrant country/economy":
        if (!isRedactedValue(value)) result.registrantCountry = value;
        break;
      case "country":
      case "country-code":
        if (!isRedactedValue(value) && result.registrantCountry === "Unknown")
          result.registrantCountry = value;
        break;

      // ── Registrant phone ──────────────────────────────────────────────────
      case "registrant phone":
      case "registrant phone number":
      case "registrant telephone":
      case "phone":
      case "telephone":
        if (!isRedactedValue(value) && result.registrantPhone === "Unknown")
          result.registrantPhone = value.replace(/^tel:/i, "").trim();
        break;

      // ── Registrant fax ────────────────────────────────────────────────────
      case "registrant fax":
      case "registrant fax ext":
      case "fax":
      case "fax-no":
      case "fax no":
      case "telefax":
        if (!isRedactedValue(value) && result.registrantFax === "Unknown")
          result.registrantFax = value.replace(/^tel:/i, "").trim();
        break;

      // ── Administrative contact ────────────────────────────────────────────
      case "admin name":
      case "administrative name":
      case "admin contact name":
      case "admin contact":
      case "administrative contact":
      case "administrative contact name":
      case "ac":
      case "admin id":
        if (!isRedactedValue(value) && result.adminName === "Unknown")
          result.adminName = value;
        break;
      case "admin organization":
      case "admin organisation":
      case "admin org":
      case "administrative organization":
      case "administrative organisation":
        if (!isRedactedValue(value) && result.adminOrganization === "Unknown")
          result.adminOrganization = value;
        break;
      case "admin email":
      case "admin e-mail":
      case "administrative email":
      case "administrative e-mail":
      case "admin contact email":
      case "ac e-mail":
        if (!isRedactedValue(value) && result.adminEmail === "Unknown")
          result.adminEmail = value;
        break;
      case "admin phone":
      case "admin telephone":
      case "administrative phone":
      case "administrative telephone":
      case "admin contact phone":
        if (!isRedactedValue(value) && result.adminPhone === "Unknown")
          result.adminPhone = value.replace(/^tel:/i, "").trim();
        break;
      case "admin country":
      case "administrative country":
        if (!isRedactedValue(value) && result.adminCountry === "Unknown")
          result.adminCountry = value;
        break;

      // ── Technical contact ─────────────────────────────────────────────────
      case "tech name":
      case "technical name":
      case "technical contact name":
      case "tech contact name":
      case "tech contact":
      case "technical contact":
        if (!isRedactedValue(value) && result.techName === "Unknown")
          result.techName = value;
        break;
      case "tech organization":
      case "tech organisation":
      case "tech org":
      case "technical organization":
      case "technical organisation":
        if (!isRedactedValue(value) && result.techOrganization === "Unknown")
          result.techOrganization = value;
        break;
      case "tech email":
      case "tech e-mail":
      case "technical email":
      case "technical e-mail":
      case "tech contact email":
        if (!isRedactedValue(value) && result.techEmail === "Unknown")
          result.techEmail = value;
        break;
      case "tech phone":
      case "tech telephone":
      case "technical phone":
      case "technical telephone":
      case "tech contact phone":
        if (!isRedactedValue(value) && result.techPhone === "Unknown")
          result.techPhone = value.replace(/^tel:/i, "").trim();
        break;

      // ── Abuse contact ─────────────────────────────────────────────────────
      case "registrar abuse contact phone":
      case "abuse phone":
      case "abuse contact phone":
        if (!isRedactedValue(value))
          result.abusePhone = value.replace(/^tel:/i, "").trim();
        break;
      case "registrar abuse contact email":
      case "abuse-mailbox":
        if (!isRedactedValue(value)) result.abuseEmail = value;
        break;
      case "orgtechphone":
        if (!isRedactedValue(value) && result.techPhone === "Unknown")
          result.techPhone = value.replace(/^tel:/i, "").trim();
        break;
      case "registrant email":
      case "registrant contact email":
        if (!isRedactedValue(value))
          result.registrantEmail = value.replace(
            "Select Request Email Form at ",
            "",
          );
        break;
      case "dnssec":
      case "dnssec status":
      case "signed":
        result.dnssec = value;
        break;
      case "email":
        if (!isRedactedValue(value) && result.registrantEmail === "Unknown")
          result.registrantEmail = value;
        break;
      case "e-mail":
        if (!isRedactedValue(value) && result.registrantEmail === "Unknown")
          result.registrantEmail = value;
        break;
      case "registrar url":
      case "referral url":
      case "registrar website":
        if (result.registrarURL === "Unknown") result.registrarURL = value;
        break;
      case "cidr":
        result.cidr = value;
        break;
      case "inetnum":
        result.inetNum = value;
        break;
      case "inet6num":
        result.inet6Num = value;
        break;
      case "netrange":
        result.netRange = value;
        break;
      case "netname":
        result.netName = value;
        break;
      case "network-name":
        result.netName = value;
        break;
      case "nettype":
        result.netType = value;
        break;
      case "originas":
        result.originAS = value;
        break;
      case "origin":
        result.originAS = value;
        break;
    }

    if (includeArgs(key, "domain name") && !result.domain && isDomainLike(value)) {
      result.domain = value;
    } else if (
      includeArgs(key, "registrar") &&
      !includeArgs(key, "expir", "date", "phone", "email", "url", "whois", "iana", "server", "abuse", "registration") &&
      result.registrar === "Unknown"
    ) {
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

  let newStatus: DomainStatusProps[] = [];
  for (let i = 0; i < result.status.length; i++) {
    const status = result.status[i];
    if (newStatus.find((item) => item.status === status.status)) continue;
    newStatus.push(status);
  }
  result.status = newStatus;

  // ── Synthetic status injection from raw WHOIS text ──────────────────────────
  // Many ccTLD WHOIS servers express domain state as free-form text rather than
  // structured EPP status codes. Detect these patterns and inject synthetic
  // status entries so downstream status detection works correctly.
  {
    const rawLow = data.toLowerCase();
    const hasStatusCode = (code: string) =>
      result.status.some((s) => s.status.toLowerCase().includes(code));

    // ── RESERVED ─────────────────────────────────────────────────────────────
    // Domain is held by the registry and not available for public registration.
    // Sources (non-exhaustive):
    //   TELE-INFO (.yun/.wang/.中文) → "in the reserved list, please contact the registry"
    //   TWNIC (.tw/.com.tw)          → standalone "Reserved" line
    //   NZRS (.nz/.co.nz)            → standalone "reserved" line
    //   DENIC (.de)                  → "% Status: reserviert" (German)
    //   EURID (.eu)                  → "Status: RESERVED"
    //   IIS (.se/.nu)                → "state: reserved"
    //   CZ.NIC (.cz/.sk)             → "rezervovan: ano" (Czech/Slovak)
    //   NIC.AT (.at)                 → "% Domain [x] is reserved."
    //   Donuts / Identity Digital    → "Status: reserved" (EPP field in WHOIS text)
    //   CentralNic / LogicBoxes      → "Status: reserved"
    //   CIRA (.ca)                   → "Status: Reserved"
    //   FICORA (.fi)                 → "Status: Reserved"
    //   CNNIC / Chinese TLD WHOIS    → "保留域名" / "已被保留" / "注册局保留"
    //   Generic ccTLD/new gTLD       → "Reserved for future use" / "reserved for official use"
    //   New gTLD sunrise periods     → "sunrise reserved" / "reserved for sunrise"
    const syntheticReserved =
      !hasStatusCode("reserved") &&
      (// ── English free-text phrases ──────────────────────────────────────
        rawLow.includes("reserved name") ||
        rawLow.includes("this name is reserved") ||
        rawLow.includes("is a reserved name") ||
        rawLow.includes("domain is reserved") ||
        rawLow.includes("this domain is reserved") ||
        rawLow.includes("domain name is reserved") ||
        rawLow.includes("reserved by the registry") ||
        rawLow.includes("registry reserved") ||
        rawLow.includes("reserved-name") ||
        rawLow.includes("reserved domain") ||
        rawLow.includes("in the reserved list") ||
        rawLow.includes("on the reserved list") ||
        rawLow.includes("is in the reserved list") ||
        rawLow.includes("is on the reserved list") ||
        rawLow.includes("has been reserved") ||
        rawLow.includes("name is reserved") ||
        rawLow.includes("is reserved for") ||
        rawLow.includes("is reserved by") ||
        rawLow.includes("reserved for registry") ||
        rawLow.includes("reserved for the registry") ||
        rawLow.includes("registry has reserved") ||
        rawLow.includes("registry hold") ||
        rawLow.includes("held by the registry") ||
        rawLow.includes("domain is held") ||
        rawLow.includes("being held by") ||
        rawLow.includes("reserved for future use") ||
        rawLow.includes("reserved for official use") ||
        rawLow.includes("reserved for this registry") ||
        rawLow.includes("reserved at the registry") ||
        rawLow.includes("sunrise reserved") ||
        rawLow.includes("reserved for sunrise") ||
        rawLow.includes("reserved for landrush") ||
        rawLow.includes("landrush reserved") ||
        // ── Structured field: "status: reserved" / "state: reserved" ────
        // Covers EURID (.eu), IIS (.se/.nu), CIRA (.ca), FICORA (.fi),
        // DNS Polska (.pl), and many new gTLD operators.
        /\bstatus\s*:\s*reserved\b/.test(rawLow) ||
        /\bstate\s*:\s*reserved\b/.test(rawLow) ||
        /\bdomainstatus\s*:\s*reserved\b/.test(rawLow) ||
        // ── German (DENIC .de): "% Status: reserviert" ──────────────────
        rawLow.includes("reserviert") ||
        /\bstatus\s*:\s*reserviert\b/.test(rawLow) ||
        // ── Czech / Slovak (CZ.NIC .cz .sk): "rezervovan: ano" ──────────
        rawLow.includes("rezervovan") ||
        // ── French ccTLD (AFNIC .fr .re .pm .tf .wf .yt) ────────────────
        rawLow.includes("réservé") ||
        rawLow.includes("domaine réservé") ||
        rawLow.includes("domaine reserve") ||
        /\bstatus\s*:\s*r[eé]serv[eé]\b/.test(rawLow) ||
        // ── Spanish ccTLD (.es, .ar, .mx, .co, .cl, .pe, .uy, etc.) ─────
        rawLow.includes("reservado") ||
        rawLow.includes("dominio reservado") ||
        /\bestado\s*:\s*reservado\b/.test(rawLow) ||
        // ── Portuguese (.pt / .br) ────────────────────────────────────────
        rawLow.includes("reservado") ||          // same spelling as Spanish
        rawLow.includes("domínio reservado") ||
        // ── Italian (NIC.it .it): status RISERVATO, SOSPESO ─────────────
        /\bstatus\s*:\s*riservato\b/.test(rawLow) ||
        rawLow.includes("dominio riservato") ||
        // ── Swedish (IIS .se .nu): "state: reserverad" ───────────────────
        /\bstate\s*:\s*reserverad\b/.test(rawLow) ||
        /\bstatus\s*:\s*reserverad\b/.test(rawLow) ||
        rawLow.includes("domännamnet är reserverat") ||  // "domain name is reserved" in Swedish
        // ── Norwegian (Norid .no): "reservert" ───────────────────────────
        /\bstatus\s*:\s*reservert\b/.test(rawLow) ||
        rawLow.includes("domenet er reservert") ||      // "domain is reserved" in Norwegian
        // ── Danish (DK Hostmaster .dk): "reserveret" ─────────────────────
        /\bstatus\s*:\s*reserveret\b/.test(rawLow) ||
        rawLow.includes("domænet er reserveret") ||     // "domain is reserved" in Danish
        // ── Polish (DNS Polska / NASK .pl): "zarezerwowany" ──────────────
        /\bstatus\s*:\s*zarezerwowany\b/.test(rawLow) ||
        rawLow.includes("domena zarezerwowana") ||      // "reserved domain" in Polish
        // ── Dutch (SIDN .nl): "gereserveerd" ─────────────────────────────
        /\bstatus\s*:\s*gereserveerd\b/.test(rawLow) ||
        rawLow.includes("domein is gereserveerd") ||    // "domain is reserved" in Dutch
        // ── Finnish (Traficom .fi): "varattu" ────────────────────────────
        /\bstatus\s*:\s*varattu\b/.test(rawLow) ||
        rawLow.includes("verkkotunnus varattu") ||      // "domain reserved" in Finnish
        rawLow.includes("on varattu") ||                // "is reserved" in Finnish
        // ── Hungarian (.hu): "fenntartott" ───────────────────────────────
        /\bstatus\s*:\s*fenntartott\b/.test(rawLow) ||
        rawLow.includes("fenntartott tartomány") ||     // "reserved domain" in Hungarian
        // ── Romanian (RoTLD .ro): "rezervat" ─────────────────────────────
        /\bstatus\s*:\s*rezervat\b/.test(rawLow) ||
        rawLow.includes("domeniu rezervat") ||          // "reserved domain" in Romanian
        // ── Turkish (NIC.TR .tr): "rezerve" ─────────────────────────────
        /\bstatus\s*:\s*rezerve\b/.test(rawLow) ||
        rawLow.includes("alan adı rezerve") ||          // "domain name reserved" in Turkish
        // ── Greek (ICS.FORTH .gr) ─────────────────────────────────────────
        rawLow.includes("δεσμευμένο") ||               // "reserved" in Greek
        // ── Russian (.ru / .рф — RU-CENTER / Coordination Center for TLD RU)
        // Non-Latin: safe to use includes() — domain names appear as punycode
        rawLow.includes("зарезервирован") ||           // reserved (masculine)
        rawLow.includes("зарезервировано") ||          // reserved (neuter)
        rawLow.includes("зарезервирована") ||          // reserved (feminine)
        rawLow.includes("домен зарезервирован") ||     // "domain is reserved" in Russian
        rawLow.includes("заблокирован") ||             // blocked/prohibited (Russian)
        // ── Ukrainian (.ua — Hostmaster.UA) ──────────────────────────────
        rawLow.includes("зарезервовано") ||            // reserved (Ukrainian)
        rawLow.includes("домен зарезервовано") ||      // "domain is reserved" in Ukrainian
        // ── Japanese (.jp — JPRS): bilingual, may contain Japanese ───────
        rawLow.includes("予約済み") ||                  // "reserved" in Japanese
        rawLow.includes("利用停止") ||                  // "service suspended" in Japanese
        rawLow.includes("登録停止") ||                  // "registration suspended" in Japanese
        // ── Korean (.kr — KRNIC): WHOIS can respond in Korean ────────────
        rawLow.includes("예약됨") ||                    // "reserved" in Korean
        rawLow.includes("예약된") ||                    // "reserved" (attributive) in Korean
        rawLow.includes("예약된 도메인") ||             // "reserved domain" in Korean
        // ── Arabic ccTLDs (.sa / .ae / .eg / .iq / .ly) ─────────────────
        rawLow.includes("محجوز") ||                    // "reserved/booked" in Arabic
        rawLow.includes("النطاق محجوز") ||             // "domain is reserved" in Arabic
        // ── Hebrew (.il — ISOC-IL) ───────────────────────────────────────
        rawLow.includes("שמור") ||                     // "reserved/saved" in Hebrew
        rawLow.includes("הדומיין שמור") ||             // "domain is reserved" in Hebrew
        // ── Traditional Chinese (.tw / .hk) ──────────────────────────────
        // Simplified already covered above; Traditional characters:
        rawLow.includes("保留網域") ||                  // "reserved domain" in Traditional Chinese
        rawLow.includes("已保留") ||                    // "already reserved" in Traditional/Simplified
        // ── Simplified Chinese WHOIS (CNNIC, TELE-INFO, ZDNS) ────────────
        rawLow.includes("保留域名") ||
        rawLow.includes("已被保留") ||
        rawLow.includes("注册局保留") ||
        rawLow.includes("保留中") ||
        rawLow.includes("该域名已保留") ||
        // ── standalone "reserved" on its own line (TWNIC / NZRS) ─────────
        /(?:^|\n)\s*reserved\s*(?:\n|$)/.test(rawLow));

    if (syntheticReserved) {
      result.status.push({ status: "registry-reserved", url: "" });
    }

    // ── PREMIUM RESERVED ─────────────────────────────────────────────────────
    // Registry is holding this name for sale at a premium price or via special
    // application / auction.  These get an additional "registry-premium" tag so
    // the UI can show a different, purchase-oriented description.
    // Sources:
    //   Many new gTLD operators    → "Premium" tier during EAP / launch periods
    //   TELE-INFO (.yun/.wang)     → "please contact the registry"
    //   Aftermarket platforms      → "available for purchase" / "make an offer"
    //   Sedo / GoDaddy Auctions    → "this name is available for purchase"
    const syntheticPremiumReserved =
      !hasStatusCode("registry-premium") &&
      (rawLow.includes("premium domain") ||
        rawLow.includes("premium name") ||
        rawLow.includes("premium price") ||
        rawLow.includes("premium pricing") ||
        rawLow.includes("premium listing") ||
        rawLow.includes("registry premium") ||
        rawLow.includes("available at a premium") ||
        rawLow.includes("this is a premium") ||
        rawLow.includes("premium registration") ||
        rawLow.includes("early access program") ||
        rawLow.includes("early access pricing") ||
        rawLow.includes("early access period") ||
        rawLow.includes("available for purchase") ||
        rawLow.includes("available for sale") ||
        rawLow.includes("this name is for sale") ||
        rawLow.includes("domain is for sale") ||
        rawLow.includes("make an offer") ||
        rawLow.includes("aftermarket") ||
        rawLow.includes("reserve price") ||
        rawLow.includes("starting bid") ||
        rawLow.includes("minimum bid") ||
        // "contact the registry/registrar" as purchase call-to-action
        rawLow.includes("please contact the registry") ||
        rawLow.includes("contact the registry to") ||
        rawLow.includes("contact the registry for") ||
        rawLow.includes("contact your registrar to") ||
        rawLow.includes("contact your registrar for") ||
        rawLow.includes("enquire about this domain") ||
        rawLow.includes("inquire about this domain") ||
        rawLow.includes("may be available for purchase") ||
        rawLow.includes("can be acquired") ||
        rawLow.includes("reach out to the registry"));

    if (syntheticPremiumReserved) {
      result.status.push({ status: "registry-premium", url: "" });
    }

    // ── PROHIBITED / BLOCKED ─────────────────────────────────────────────────
    // Domain string is policy-blocked and cannot be registered by anyone.
    // Sources:
    //   ICANN policy       → prohibited strings, brand protection
    //   Registry policy    → sensitive keywords, govt-reserved terms
    //   ccTLD policy       → national policy blocks
    //   DNS abuse lists    → malware / phishing holds
    const syntheticProhibited =
      !hasStatusCode("prohibited") &&
      !hasStatusCode("blocked") &&
      (rawLow.includes("registration is prohibited") ||
        rawLow.includes("registration prohibited") ||
        rawLow.includes("cannot be registered") ||
        rawLow.includes("registration not possible") ||
        rawLow.includes("registration not available") ||
        rawLow.includes("not available for registration") ||
        rawLow.includes("not eligible for registration") ||
        rawLow.includes("not open for registration") ||
        rawLow.includes("not open for general registration") ||
        rawLow.includes("not open to general registrations") ||
        rawLow.includes("not currently open for registration") ||
        rawLow.includes("not available for public registration") ||
        rawLow.includes("not permitted to register") ||
        rawLow.includes("registration is not permitted") ||
        rawLow.includes("registrations are not permitted") ||
        rawLow.includes("registrations not permitted") ||
        rawLow.includes("not accepting registrations") ||
        rawLow.includes("registrations not accepted") ||
        rawLow.includes("no registrations are accepted") ||
        rawLow.includes("does not accept registrations") ||
        rawLow.includes("cannot be publicly registered") ||
        rawLow.includes("prohibited string") ||
        rawLow.includes("prohibited by policy") ||
        rawLow.includes("policy prohibited") ||
        rawLow.includes("not available for public use") ||
        rawLow.includes("registrar banned") ||
        rawLow.includes("registry banned") ||
        rawLow.includes("blacklisted") ||
        rawLow.includes("禁止注册") ||         // Chinese: registration prohibited
        rawLow.includes("不开放注册") ||       // Chinese: not open for registration
        rawLow.includes("不可注册") ||         // Chinese: cannot register
        rawLow.includes("禁止使用") ||         // Chinese: prohibited from use
        // ── Russian / Ukrainian ──────────────────────────────────────────
        rawLow.includes("запрещена регистрация") ||  // "registration is prohibited" (Russian)
        rawLow.includes("регистрация запрещена") ||  // "registration prohibited" (Russian)
        rawLow.includes("реєстрація заборонена") ||  // "registration prohibited" (Ukrainian)
        // ── Italian (NIC.it .it) ─────────────────────────────────────────
        /\bstatus\s*:\s*vietato\b/.test(rawLow) ||    // "prohibited" in Italian
        rawLow.includes("registrazione vietata") ||   // "registration prohibited" in Italian
        // ── Japanese (.jp — JPRS) ────────────────────────────────────────
        rawLow.includes("登録不可") ||        // "cannot register" in Japanese
        rawLow.includes("登録制限") ||        // "registration restricted" in Japanese
        // ── Korean (.kr — KRNIC) ─────────────────────────────────────────
        rawLow.includes("등록불가") ||        // "cannot register" in Korean
        rawLow.includes("등록 금지") ||       // "registration prohibited" in Korean
        // ── Arabic ccTLDs ────────────────────────────────────────────────
        rawLow.includes("محظور") ||           // "prohibited/forbidden" in Arabic
        rawLow.includes("التسجيل محظور") ||   // "registration is prohibited" in Arabic
        /\bblocked\s+by\s+(?:registry|registrar)\b/.test(rawLow) ||
        /\bregistration\s+blocked\b/.test(rawLow));

    if (syntheticProhibited) {
      result.status.push({ status: "registrationProhibited", url: "" });
    }

    // ── SUSPENDED / HOLD ─────────────────────────────────────────────────────
    // Domain was registered but has been suspended by the registry or registrar.
    // Sources:
    //   Registrar action   → non-payment, policy violation, abuse report
    //   Registry action    → ICANN compliance, court orders, fraud holds
    //   ccTLD policies     → national law enforcement, consumer protection
    const syntheticSuspended =
      !hasStatusCode("suspended") &&
      !hasStatusCode("hold") &&
      (rawLow.includes("suspended by registry") ||
        rawLow.includes("suspended by registrar") ||
        rawLow.includes("registry-suspended") ||
        rawLow.includes("domain is suspended") ||
        rawLow.includes("domain suspended") ||
        rawLow.includes("domain has been suspended") ||
        rawLow.includes("account suspended") ||
        rawLow.includes("abuse suspension") ||
        rawLow.includes("abuse hold") ||
        rawLow.includes("fraud hold") ||
        rawLow.includes("compliance hold") ||
        rawLow.includes("billing suspension") ||
        rawLow.includes("domain is on hold") ||
        rawLow.includes("registrar hold") ||
        rawLow.includes("gesperrt") ||          // German: locked/blocked (DENIC .de)
        rawLow.includes("suspendido") ||        // Spanish: suspended
        rawLow.includes("suspendu") ||          // French: suspended (AFNIC .fr)
        // ── Portuguese (.pt / .br) ────────────────────────────────────────
        rawLow.includes("suspenso") ||          // Portuguese: suspended
        rawLow.includes("domínio suspenso") ||  // "suspended domain" in Portuguese
        // ── Italian (NIC.it .it) ─────────────────────────────────────────
        /\bstatus\s*:\s*sospeso\b/.test(rawLow) ||  // "suspended" in Italian
        rawLow.includes("dominio sospeso") ||   // "suspended domain" in Italian
        // ── Dutch (.nl) ───────────────────────────────────────────────────
        rawLow.includes("opgeschort") ||        // "suspended" in Dutch
        rawLow.includes("domein opgeschort") || // "domain suspended" in Dutch
        // ── Polish (DNS Polska .pl) ───────────────────────────────────────
        rawLow.includes("zawieszony") ||        // "suspended" in Polish
        rawLow.includes("domena zawieszona") || // "suspended domain" in Polish
        // ── Finnish (Traficom .fi) ────────────────────────────────────────
        rawLow.includes("keskeytetty") ||       // "suspended" in Finnish
        // ── Russian (.ru / .рф) ───────────────────────────────────────────
        rawLow.includes("приостановлен") ||     // "suspended" (masc.) in Russian
        rawLow.includes("приостановлено") ||    // "suspended" (neut.) in Russian
        rawLow.includes("домен заблокирован") || // "domain is blocked" in Russian
        // ── Ukrainian (.ua) ───────────────────────────────────────────────
        rawLow.includes("призупинено") ||       // "suspended" in Ukrainian
        // ── Japanese (.jp — JPRS) ────────────────────────────────────────
        rawLow.includes("停止中") ||            // "in suspension" in Japanese
        rawLow.includes("利用停止") ||          // "service suspended" in Japanese
        // ── Korean (.kr — KRNIC) ─────────────────────────────────────────
        rawLow.includes("정지됨") ||            // "suspended" in Korean
        rawLow.includes("사용 정지") ||         // "service suspended" in Korean
        // ── Arabic ccTLDs ────────────────────────────────────────────────
        rawLow.includes("موقوف") ||            // "suspended/on hold" in Arabic
        rawLow.includes("معلق") ||             // "suspended/pending" in Arabic
        // ── Chinese WHOIS ─────────────────────────────────────────────────
        rawLow.includes("已暂停") ||            // "already suspended" (Simplified)
        rawLow.includes("域名暂停") ||          // "domain suspended" (Simplified)
        rawLow.includes("已停用") ||            // "already disabled" (Simplified)
        rawLow.includes("暫停使用") ||          // "suspended from use" (Traditional)
        // standalone "suspended" on its own line
        /(?:^|\n)\s*suspended\s*(?:\n|$)/.test(rawLow));

    if (syntheticSuspended) {
      result.status.push({ status: "suspended", url: "" });
    }
  }

  const seenNS = new Set<string>();
  result.nameServers = result.nameServers.filter((ns) => {
    const nsKey = ns.toLowerCase().trim();
    if (!nsKey || seenNS.has(nsKey)) return false;
    seenNS.add(nsKey);
    return true;
  });

  if (result.creationDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "creat", "registered", "activation", "anniversary", "inception",
      "enregistr", "registro", "criado",
    ]);
    if (fallback) result.creationDate = fallback;
  }

  if (result.expirationDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "expir", "valid until", "paid-till", "paid till", "renewal",
      "due date", "venc", "ablauf", "validade",
    ]);
    if (fallback) result.expirationDate = fallback;
  }

  if (result.updatedDate === "Unknown") {
    const fallback = extractDateNearKeyword(data, [
      "updated", "modified", "last change", "last update", "mise à jour",
      "mise a jour", "modificat", "actualiz",
    ]);
    if (fallback) result.updatedDate = fallback;
  }

  if (explicitUnicodeDomain) {
    result.domain = explicitUnicodeDomain;
    if (explicitAsciiDomain) {
      result.domainPunycode = explicitAsciiDomain.toUpperCase();
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
