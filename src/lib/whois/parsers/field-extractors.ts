/**
 * Field-family extractors for WHOIS key/value lines.
 *
 * The original analyzeWhois() switch grew to hundreds of cases spanning every
 * registry layout. It is now split by field family — domain identity, dates,
 * status, nameservers, registrant/admin/tech/abuse contacts and IP-network
 * fields — and exposed as a single label -> extractor map.
 *
 * Every handler receives the already-normalised value plus the result object
 * and a small mutable context (for the explicit Unicode/ASCII domain pair).
 * Behaviour is locked by common-parser-golden.test.ts: adding or moving a
 * handler must not change the recorded output for any label.
 */

import { WhoisAnalyzeResult } from "@/lib/whois/types";
import {
  isDomainLike,
  isRedactedValue,
  analyzeDomainStatus,
} from "@/lib/whois/parsers/utils";
import { analyzeTime } from "@/lib/whois/parsers/date";

export interface ExtractContext {
  explicitUnicodeDomain: string;
  explicitAsciiDomain: string;
}

export type FieldExtractor = (
  value: string,
  result: WhoisAnalyzeResult,
  ctx: ExtractContext,
) => void;

const stripTel = (value: string): string =>
  value.replace(/^tel:/i, "").trim();

// ── Domain identity ──────────────────────────────────────────────────────────

const domainExtractors: Record<string, FieldExtractor> = {
  "domain name (unicode)": (value, _result, ctx) => {
    if (!ctx.explicitUnicodeDomain) ctx.explicitUnicodeDomain = value;
  },
  "domain name (ascii)": (value, result, ctx) => {
    if (!ctx.explicitAsciiDomain) ctx.explicitAsciiDomain = value;
    if (isDomainLike(value)) result.domain = result.domain || value;
  },
  "domain name": (value, result) => {
    if (isDomainLike(value)) result.domain = result.domain || value;
  },
  registrar: (value, result) => {
    result.registrar =
      result.registrar === "Unknown" ? value : result.registrar;
  },
  "iana id": (value, result) => {
    result.ianaId = value;
  },
  "registrar iana id": (value, result) => {
    result.ianaId = value;
  },
  "whois server": (value, result) => {
    result.whoisServer = value;
  },
  whois: (value, result) => {
    result.whoisServer = value;
  },
  "registrar whois server": (value, result) => {
    result.whoisServer = value;
  },
  "registrar url": (value, result) => {
    if (result.registrarURL === "Unknown") result.registrarURL = value;
  },
};

// ── Dates ────────────────────────────────────────────────────────────────────

const dateExtractors: Record<string, FieldExtractor> = {
  "updated date": (value, result) => {
    if (result.updatedDate === "Unknown")
      result.updatedDate = analyzeTime(value);
  },
  "creation date": (value, result) => {
    if (result.creationDate === "Unknown")
      result.creationDate = analyzeTime(value);
  },
  "domain name commencement date": (value, result) => {
    if (result.creationDate === "Unknown")
      result.creationDate = analyzeTime(value);
  },
  "expiration date": (value, result) => {
    if (result.expirationDate === "Unknown")
      result.expirationDate = analyzeTime(value);
  },
};

// ── Status ───────────────────────────────────────────────────────────────────

const statusExtractors: Record<string, FieldExtractor> = {
  state: (value, result) => {
    const expiryMatch = value.match(/\((\d{4}\/\d{2}\/\d{2})\)/);
    if (expiryMatch && result.expirationDate === "Unknown") {
      result.expirationDate = analyzeTime(expiryMatch[1]);
    }
    result.status.push(analyzeDomainStatus(value));
  },
  status: (value, result) => {
    result.status.push(analyzeDomainStatus(value));
  },
  "domain status": (value, result) => {
    result.status.push(analyzeDomainStatus(value));
  },
};

// ── Nameservers ──────────────────────────────────────────────────────────────

const nameserverExtractors: Record<string, FieldExtractor> = {
  // .kz (KazNIC) lists nameservers as Primary/Secondary server.
  // Split on commas (e.g. "ns1.foo.com, ns2.foo.com") then strip IPs.
  "name server": (value, result) => {
    for (const nsEntry of value.split(",")) {
      const ns = nsEntry.trim().split(/\s+/)[0];
      if (ns && ns.includes(".")) result.nameServers.push(ns);
    }
  },
};

// ── Registrant contact ───────────────────────────────────────────────────────

const registrantExtractors: Record<string, FieldExtractor> = {
  "registry domain id": (value, result) => {
    if (result.registryDomainId === "Unknown") result.registryDomainId = value;
  },
  "registrant name": (value, result) => {
    if (!isRedactedValue(value) && result.registrantName === "Unknown")
      result.registrantName = value;
  },
  "registrant organization": (value, result) => {
    if (!isRedactedValue(value)) result.registrantOrganization = value;
  },
  organization: (value, result) => {
    if (!isRedactedValue(value) && result.registrantOrganization === "Unknown")
      result.registrantOrganization = value;
  },
  registrant: (value, result) => {
    // A bare "Registrant" value is the registrant's name/handle (common in
    // .cn CNNIC English output and .vn / .kr ccTLD whois). Only use it for
    // the name field while both name and organization are still unset.
    if (
      !isRedactedValue(value) &&
      result.registrantName === "Unknown" &&
      result.registrantOrganization === "Unknown"
    ) {
      result.registrantName = value;
    }
  },
  descr: (value, result) => {
    if (!isRedactedValue(value) && result.registrantOrganization === "Unknown")
      result.registrantOrganization = value;
  },
  "registrant state/province": (value, result) => {
    if (!isRedactedValue(value) && result.registrantProvince === "Unknown")
      result.registrantProvince = value;
  },
  "registrant city": (value, result) => {
    if (!isRedactedValue(value) && result.registrantCity === "Unknown")
      result.registrantCity = value;
  },
  "registrant street": (value, result) => {
    if (!isRedactedValue(value) && result.registrantAddress === "Unknown")
      result.registrantAddress = value;
  },
  "registrant postal code": (value, result) => {
    if (!isRedactedValue(value) && result.registrantPostalCode === "Unknown")
      result.registrantPostalCode = value;
  },
  "registrant country": (value, result) => {
    if (!isRedactedValue(value)) result.registrantCountry = value;
  },
  country: (value, result) => {
    if (!isRedactedValue(value) && result.registrantCountry === "Unknown")
      result.registrantCountry = value;
  },
  "registrant phone": (value, result) => {
    if (!isRedactedValue(value) && result.registrantPhone === "Unknown")
      result.registrantPhone = stripTel(value);
  },
  "registrant fax": (value, result) => {
    if (!isRedactedValue(value) && result.registrantFax === "Unknown")
      result.registrantFax = stripTel(value);
  },
  "registrant email": (value, result) => {
    if (!isRedactedValue(value))
      result.registrantEmail = value.replace(
        "Select Request Email Form at ",
        "",
      );
  },
  email: (value, result) => {
    if (!isRedactedValue(value) && result.registrantEmail === "Unknown")
      result.registrantEmail = value;
  },
};

// ── Administrative contact ───────────────────────────────────────────────────

const adminExtractors: Record<string, FieldExtractor> = {
  "admin name": (value, result) => {
    if (!isRedactedValue(value) && result.adminName === "Unknown")
      result.adminName = value;
  },
  "admin organization": (value, result) => {
    if (!isRedactedValue(value) && result.adminOrganization === "Unknown")
      result.adminOrganization = value;
  },
  "admin email": (value, result) => {
    if (!isRedactedValue(value) && result.adminEmail === "Unknown")
      result.adminEmail = value;
  },
  "admin phone": (value, result) => {
    if (!isRedactedValue(value) && result.adminPhone === "Unknown")
      result.adminPhone = stripTel(value);
  },
  "admin country": (value, result) => {
    if (!isRedactedValue(value) && result.adminCountry === "Unknown")
      result.adminCountry = value;
  },
};

// ── Technical contact ────────────────────────────────────────────────────────

const techExtractors: Record<string, FieldExtractor> = {
  "tech name": (value, result) => {
    if (!isRedactedValue(value) && result.techName === "Unknown")
      result.techName = value;
  },
  "tech organization": (value, result) => {
    if (!isRedactedValue(value) && result.techOrganization === "Unknown")
      result.techOrganization = value;
  },
  "tech email": (value, result) => {
    if (!isRedactedValue(value) && result.techEmail === "Unknown")
      result.techEmail = value;
  },
  "tech phone": (value, result) => {
    if (!isRedactedValue(value) && result.techPhone === "Unknown")
      result.techPhone = stripTel(value);
  },
  // ARIN's org-tech phone abbreviation.
  orgtechphone: (value, result) => {
    if (!isRedactedValue(value) && result.techPhone === "Unknown")
      result.techPhone = stripTel(value);
  },
};

// ── Abuse contact ────────────────────────────────────────────────────────────

const abuseExtractors: Record<string, FieldExtractor> = {
  "registrar abuse contact phone": (value, result) => {
    if (!isRedactedValue(value)) result.abusePhone = stripTel(value);
  },
  "registrar abuse contact email": (value, result) => {
    if (!isRedactedValue(value)) result.abuseEmail = value;
  },
};

// ── Misc ─────────────────────────────────────────────────────────────────────

const miscExtractors: Record<string, FieldExtractor> = {
  dnssec: (value, result) => {
    result.dnssec = value;
  },
};

// ── IP network (ARIN/RIPE/APNIC inetnum blocks) ──────────────────────────────

const networkExtractors: Record<string, FieldExtractor> = {
  cidr: (value, result) => {
    result.cidr = value;
  },
  inetnum: (value, result) => {
    result.inetNum = value;
  },
  inet6num: (value, result) => {
    result.inet6Num = value;
  },
  netrange: (value, result) => {
    result.netRange = value;
  },
  netname: (value, result) => {
    result.netName = value;
  },
  "network-name": (value, result) => {
    result.netName = value;
  },
  nettype: (value, result) => {
    result.netType = value;
  },
  originas: (value, result) => {
    result.originAS = value;
  },
  origin: (value, result) => {
    result.originAS = value;
  },
};

export const FIELD_EXTRACTORS: Readonly<Record<string, FieldExtractor>> = {
  ...domainExtractors,
  ...dateExtractors,
  ...statusExtractors,
  ...nameserverExtractors,
  ...registrantExtractors,
  ...adminExtractors,
  ...techExtractors,
  ...abuseExtractors,
  ...miscExtractors,
  ...networkExtractors,
};
